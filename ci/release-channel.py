#!/usr/bin/env python3
"""Build, publish, independently read, then advance immutable source channels.

Managed source: dave-fork-ci/ci/release-channel.py. No activation or deletion.
Only the promote command has forge write credentials.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from http.client import HTTPException
import importlib.util
import json
import os
from pathlib import Path
from queue import Empty, SimpleQueue
import re
import subprocess
import sys
import tempfile
from threading import Condition, Thread
import time
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

# Never write bytecode: consumers once tracked ci/__pycache__ and the rewrite
# dirtied the checkout that the clean-checkout checks require.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CACHE = 'https://niks3.monke.fail'
CACHE = 'https://niks3.monke.fail' + ('/oidc' if json.loads((ROOT/'ci/channels.json').read_text()).get('forge') == 'github' else '')
KEY = 'niks3.monke.fail-1:q13GqiZgAxx7SyoLZInXoJjviZMOdNpfG03xs0VUD2M='
UPSTREAM = 'https://cache.nixos.org'
UPSTREAM_KEY = 'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='
# Signer of the historical NARs in retained archives (ci/retained-archives.md);
# trusted only when verifying those exact archived paths.
LEGACY_KEY = 'flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8='
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+')
SHA = re.compile(r'[a-f0-9]{40}')
FLAGS = ['--option', 'accept-flake-config', 'false', '--no-update-lock-file', '--no-write-lock-file']
NO_BUILD = ['--option', 'max-jobs', '0', '--option', 'builders', '', '--option', 'fallback', 'false']


ACTIVE_PHASE = 'startup'
# GitHub serves job logs only after a job ends. Trusted GitHub release jobs
# receive STATUS_TOKEN (checks: write) and keep one check run per system up to
# date, so `gh api repos/OWNER/NAME/commits/SHA/check-runs` shows live progress.
PROGRESS = {'system': None, 'sha': None, 'id': None, 'last': 0.0, 'disabled': False}
PROGRESS_INTERVAL = 15


def phase(label):
    global ACTIVE_PHASE
    if not re.fullmatch(r'[a-z-]+', label):
        raise ValueError('Invalid release phase')
    ACTIVE_PHASE = label
    print('Release phase: ' + label, flush=True)


def progress_request(method, path, body):
    import urllib.request
    request = urllib.request.Request(
        'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + path,
        data=json.dumps(body).encode(), method=method,
        headers={'Authorization': 'Bearer ' + os.environ['STATUS_TOKEN'], 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'release-channel-progress'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read() or b'{}')


def progress(description, state='pending', force=False):
    """Best effort live progress; never fails the gate and never reaches Nix."""
    if (PROGRESS['disabled'] or not os.environ.get('STATUS_TOKEN') or not PROGRESS['sha'] or not PROGRESS['system']
            or os.environ.get('GITHUB_SERVER_URL') != 'https://github.com'
            or not re.fullmatch(r'[\w.-]+/[\w.-]+', os.environ.get('GITHUB_REPOSITORY', ''))):
        return False
    now = time.monotonic()
    final = state != 'pending'
    if not (force or final) and now - PROGRESS['last'] < PROGRESS_INTERVAL:
        return False
    title = (PROGRESS['system'] + ' ' + description)[:200]
    body = {'output': {'title': title, 'summary': title + '\n\nPhase: `' + ACTIVE_PHASE + '`'}}
    if final:
        body.update(status='completed', conclusion='success' if state == 'success' else 'failure')
    else:
        body['status'] = 'in_progress'
    try:
        if PROGRESS['id'] is None:
            body.update(name='release progress / ' + PROGRESS['system'], head_sha=PROGRESS['sha'])
            if re.fullmatch(r'\d+', os.environ.get('GITHUB_RUN_ID', '')):
                body['details_url'] = ('https://github.com/' + os.environ['GITHUB_REPOSITORY']
                                       + '/actions/runs/' + os.environ['GITHUB_RUN_ID'])
            created = progress_request('POST', '/check-runs', body)
            if not isinstance(created.get('id'), int):
                raise ValueError('No check run id')
            PROGRESS['id'] = created['id']
        else:
            progress_request('PATCH', '/check-runs/' + str(PROGRESS['id']), body)
    except Exception:
        # Progress is advisory. Stop after the first failure instead of
        # slowing every later target with timeouts.
        PROGRESS['disabled'] = True
        print('Release progress check run unavailable; continuing without it', file=sys.stderr, flush=True)
        return False
    PROGRESS['last'] = now
    return True


class CommandFailure(RuntimeError):
    """A fixed diagnostic category, never raw subprocess output or arguments."""

    def __init__(self, message, category=None):
        super().__init__(message)
        self.category = category


def failure_category(diagnostic):
    patterns = [
        ('source-hash-mismatch', r'hash mismatch in fixed-output derivation'),
        ('cache-integrity', r'nar.*hash mismatch|corrupted path|invalid nar'),
        ('cache-metadata-mismatch', r'published metadata differs|publication changed'),
        ('cache-missing-output', r'incomplete cache publication|required cache output is missing'),
        ('cache-signature', r'lacks a signature|is not signed|invalid signature|no trusted signature|is untrusted'),
        ('authorization', r'HTTP[^\n]*(?:401|403)|unauthorized|forbidden|authentication failed'),
        ('daemon-unavailable', r"remote store 'daemon'|cannot connect to socket|daemon-socket"),
        ('transport', r'unexpected eof|http/2|framing|connection reset|timed out|timeout|internalservererror|HTTP[^\n]*50[0-9]|'
                      r'could not resolve host|resolving timed out|temporary failure in name resolution|connection refused|'
                      r'couldn.t connect|failed to connect|ssl connect error|partial file|transfer closed'),
        ('missing-input-or-output', r'HTTP[^\n]*404|does not exist|no such file|is not valid'),
        ('evaluation', r'evaluation aborted|attribute[^\n]*missing|syntax error|infinite recursion|assertion'),
        ('build', r'builder for[^\n]*failed|ninja[^\n]*stopped|failed with exit code'),
    ]
    return next((name for name, pattern in patterns if re.search(pattern, diagnostic, re.I)), 'command-failed')


def safe_detail(diagnostic):
    # Last few Nix error lines, with credentials, URL userinfo and long output removed.
    lines = [l.strip() for l in diagnostic.splitlines() if l.strip().startswith('error:')][-3:]
    text = ' | '.join(lines)
    text = re.sub(r'/nix/store/[0-9a-z]{32}-\S*', '<store-path>', text)
    text = re.sub(r'(https?://)[^/@\s]+@', r'\1***@', text)
    text = re.sub(r'\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+', '***', text)
    return text[:300]


# Only transport-class failures of idempotent `nix` commands are retried. Hash,
# signature, authorization, evaluation and build failures are never retried.
TRANSPORT_RETRY_DELAYS = (20, 60, 120)
RETRYABLE = {'transport', 'daemon-unavailable'}
# Read-only commands that only fetch metadata or sources may retry any transport
# failure. For every other `nix` command (builds) only a daemon that could not be
# reached is retried: that failed before any work was done.
READ_ONLY = {'eval', 'path-info', 'copy', 'store'}
DAEMON_SOCKET = Path('/nix/var/nix/daemon-socket/socket')


def daemon_healthy():
    try:
        return subprocess.run(['nix', 'store', 'info', '--store', 'daemon', '--json'], cwd=ROOT, text=True,
                              capture_output=True, timeout=90).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ensure_daemon():
    """Verify the job's isolated Nix daemon; restart it once or fail with a clear category."""
    if os.environ.get('NIX_REMOTE') != 'daemon' or daemon_healthy():
        return
    print('Isolated Nix daemon is unhealthy; restarting it', file=sys.stderr, flush=True)
    log = open('/tmp/nix-daemon.log', 'ab')
    env = {k: v for k, v in os.environ.items() if k != 'NIX_REMOTE'}
    try:
        child = subprocess.Popen(['nix-daemon'], stdout=log, stderr=log, env=env, start_new_session=True)
    except OSError:
        raise CommandFailure('daemon-unavailable: nix-daemon could not be started', 'daemon-unavailable') from None
    for _ in range(30):
        if DAEMON_SOCKET.exists() and child.poll() is None:
            break
        time.sleep(1)
    if child.poll() is None and daemon_healthy():
        print('Isolated Nix daemon restarted', file=sys.stderr, flush=True)
        return
    raise CommandFailure('daemon-unavailable: the isolated Nix daemon is down and could not be restarted '
                         '(see /tmp/nix-daemon.log on the runner)', 'daemon-unavailable')


def with_transport_retries(args, attempt, sleep=None):
    """Call attempt() again after transport-class failures of `nix` commands."""
    is_nix = bool(args) and Path(str(args[0])).name == 'nix'
    retryable = RETRYABLE if is_nix and len(args) > 1 and args[1] in READ_ONLY else {'daemon-unavailable'}
    delays = iter(TRANSPORT_RETRY_DELAYS if is_nix else ())
    while True:
        try:
            return attempt()
        except CommandFailure as error:
            delay = next(delays, None)
            if delay is None or error.category not in retryable:
                raise
            print('Retrying after ' + error.category + ' failure in ' + str(delay) + 's', file=sys.stderr, flush=True)
            (sleep or time.sleep)(delay)
            ensure_daemon()


def run(*args, env=None, deadline=None):
    def attempt():
        timeout = 6*3600 if deadline is None else probe_time_left(deadline)
        try:
            result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            if deadline is not None:
                raise TimeoutError from None
            raise CommandFailure('command deadline exceeded') from None
        if result.returncode:
            # Nix diagnostics may contain private paths or authenticated URLs. Emit
            # the classification, the status and a redacted tail of Nix error lines.
            diagnostic = (result.stderr or '') + '\n' + (result.stdout or '')
            category = failure_category(diagnostic)
            # Evaluation runs with builds disabled, so "Cannot build" there means a
            # source or substitute could not be fetched, not a genuine build failure.
            if (len(args) > 1 and args[1] == 'eval' and category in {'command-failed', 'build'}
                    and re.search(r"cannot build '", diagnostic, re.I)):
                category = 'transport'
            message = category + ' (exit ' + str(result.returncode) + ')'
            detail = safe_detail(diagnostic)
            raise CommandFailure(message + (': ' + detail if detail else ''), category)
        return result.stdout.strip()
    return with_transport_retries(args, attempt) if deadline is None else attempt()


def dirty_tracked_paths(limit=20):
    """Names (never contents) of tracked files that differ from HEAD."""
    try:
        result = subprocess.run(['git', 'status', '--porcelain', '-z', '--untracked-files=no'], cwd=ROOT, text=True,
                                capture_output=True, timeout=300)
    except (subprocess.SubprocessError, OSError):
        return []
    names = [entry[3:] for entry in result.stdout.split('\0') if len(entry) > 3]
    return names[:limit] + (['... and ' + str(len(names) - limit) + ' more'] if len(names) > limit else [])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def policy():
    value = json.loads((ROOT / 'ci/channels.json').read_text())
    if (value.get('version') != 1 or (not value.get('targets') and not value.get('excludedSystems')) or
            not re.fullmatch(r'[\w.-]+/[\w.-]+', value.get('repository', ''))):
        raise ValueError('Invalid channel policy')
    if value.get('forge') not in {'github', 'forgejo'} or value.get('remote') != (
            ('https://github.com/' if value['forge'] == 'github' else 'https://git.monke.fail/')+value['repository']+'.git'):
        raise ValueError('Unreviewed forge destination')
    cache_only = value.get('cacheOnlySystems', [])
    if cache_only and (value.get('kind') != 'fleet' or value['forge'] != 'forgejo'
                       or cache_only != ['aarch64-darwin'] or set(cache_only) & set(value['targets'])):
        raise ValueError('Cache-only coverage must be an explicit private fleet Darwin scope')
    excluded = value.get('excludedSystems', [])
    if (any(s not in {'aarch64-darwin', 'x86_64-darwin'} for s in excluded)
            or (excluded and value['forge'] != 'forgejo')
            or set(excluded) & set(value['targets'])):
        raise ValueError('Only explicitly excluded private Darwin systems may be omitted')
    for system, targets in value['targets'].items():
        if system not in {'x86_64-linux', 'aarch64-linux', 'aarch64-darwin', 'x86_64-darwin'} or not targets:
            raise ValueError('Empty or unsupported required system')
        for index, target in enumerate(targets, 1):
            expression = (r'(?:nixosConfigurations|nixOnDroidConfigurations)\.[\w+-]+\..+'
                          if value.get('kind') == 'fleet' else r'(packages|cacheOnlyPackages)\.[\w+-]+\.[\w+-]+')
            if (not re.fullmatch(expression, target['attribute'])
                    or (value.get('kind') != 'fleet' and target['attribute'].split('.')[1] != system)
                    or target['visibility'] not in {'public', 'cache-only', 'private'}):
                raise ValueError('Invalid target')
            if value['forge'] == 'github' and target['visibility'] == 'private':
                raise ValueError('Private source cannot use GitHub')
    inventory_file = ROOT / 'nix/platforms.json'
    if inventory_file.exists():
        inventory = json.loads(inventory_file.read_text())
        owners_file = ROOT / 'nix/forks.json'
        owners = ({p for entry in json.loads(owners_file.read_text()).values() for p in entry['packages']}
                  if owners_file.exists() and not value.get('integrationInventory') else set())
        expected = {'packages.'+s+'.'+p for s, ps in inventory.items() for p in ps if p not in owners}
        cache_only = ROOT / 'nix/cache-only-platforms.json'
        if cache_only.exists():
            expected |= {'cacheOnlyPackages.'+s+'.'+p for s, ps in json.loads(cache_only.read_text()).items() for p in ps}
        actual = {t['attribute'] for ts in value['targets'].values() for t in ts}
        if actual != expected:
            raise ValueError('Channel policy does not cover the current package/platform inventory')
    return value


def module(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), ROOT / 'ci' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@contextmanager
def build_environment(env):
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def info(paths, env, store=None, **kwargs):
    args = ['nix', 'path-info', '--json']
    if store:
        args += ['--store', store]
    else:
        args += ['--recursive']
    value = json.loads(run(*args, *paths, env=env, **kwargs))
    if isinstance(value, list):
        value = {entry['path']: entry for entry in value}
    if not isinstance(value, dict):
        raise ValueError('Invalid closure')
    return value


def metadata(entry):
    if (not isinstance(entry, dict) or type(entry.get('narSize')) is not int
            or not isinstance(entry.get('narHash'), str) or not isinstance(entry.get('references'), list)
            or any(not STORE.fullmatch(p) for p in entry['references'])):
        raise ValueError('Incomplete closure metadata')
    return {k: sorted(entry[k]) if k == 'references' else entry[k]
            for k in ['narHash', 'narSize', 'references']}


def report_metadata_difference(path, roots, origin, expected, actual, recheck=False, action='rejected'):
    # Only fixed field labels and one-way digests leave the verifier. Paths,
    # reference lists, credentials and raw remote metadata remain suppressed.
    detail = {'root': path in roots, 'origin': 'niks3' if origin == CACHE else 'upstream',
              'read': 'fresh' if recheck else 'initial', 'action': action,
              'fields': [k for k in ['narHash', 'narSize', 'references'] if expected[k] != actual[k]],
              'pathDigest': hashlib.sha256(path.encode()).hexdigest(),
              'expectedMetadataDigest': digest(expected), 'actualMetadataDigest': digest(actual)}
    print('Cache metadata mismatch: ' + json.dumps(detail, sort_keys=True), flush=True)


def remote_env(env, directory):
    # Isolated metadata DB; no success from the builder's local store/cache DB.
    return dict(env, XDG_CACHE_HOME=str(directory), NIX_CACHE_HOME=str(directory),
                NIX_CONFIG=env.get('NIX_CONFIG', '') + '\nsubstituters =\nextra-substituters =\n'
                'trusted-public-keys = ' + KEY + ' ' + UPSTREAM_KEY + '\nextra-trusted-public-keys =\n'
                'require-sigs = true\nfallback = false\nnarinfo-cache-negative-ttl = 0\n'
                'narinfo-cache-positive-ttl = 86400\ndownload-attempts = 5\n'
                'http2 = ' + ('true' if os.environ.get('CACHE_HTTP2') == 'true' else 'false') + '\n')


def verify(roots, expected, env, archived_cache=None, archived_paths=()):
    if not roots or not expected or not set(roots) <= set(expected):
        raise ValueError('Missing required output')
    if any(not STORE.fullmatch(p) or p.endswith('.drv') for p in expected):
        raise ValueError('Invalid closure path')
    expected = {p: metadata(e) for p, e in expected.items()}
    if any(ref not in expected for e in expected.values() for ref in e['references']):
        raise ValueError('Incomplete closure')
    # Roots must come from our publisher. Dependencies can use the reviewed
    # upstream cache when the publisher skipped them as already upstream.
    origins = {}
    adopted = []
    with tempfile.TemporaryDirectory(prefix='channel-read-') as directory:
        reader = remote_env(env, directory)
        for path, entry in list(expected.items()):
            candidates = ([archived_cache] if path in archived_paths else
                          [CACHE] if path in roots else [CACHE, UPSTREAM])
            for origin in candidates:
                selected_reader = reader
                if origin == archived_cache:
                    # The archive itself was freshly verified/copied from Niks3.
                    # Only its exact historical NARs may use the original signer.
                    selected_reader = dict(reader, NIX_CONFIG=reader['NIX_CONFIG'] +
                                           '\ntrusted-public-keys = ' + KEY + ' ' + UPSTREAM_KEY + ' ' + LEGACY_KEY + '\n')
                try:
                    remote = info([path], selected_reader, origin)
                except RuntimeError:
                    if origin == UPSTREAM or path in roots:
                        raise
                    continue
                if remote.get(path) is None:
                    continue
                actual = metadata(remote[path])
                if actual != entry:
                    # Another publisher already holds a different build of this
                    # input-addressed path, and the cache keeps that first copy. A
                    # non-reproducible rebuild cannot replace it. Adopt the
                    # signed cached copy only when its references match, then
                    # read and verify its bytes like any other member. Both
                    # metadata digests are logged.
                    adopt = archived_cache is None and origin == CACHE and actual['references'] == entry['references']
                    report_metadata_difference(path, roots, origin, entry, actual,
                                               action='adopted' if adopt else 'rejected')
                    if not adopt:
                        raise ValueError('Published metadata differs from build')
                    expected[path] = actual
                    adopted.append(path)
                # Reads NAR bytes, verifies hash and signature; no --no-contents,
                # local-store fallback, source build or metadata-only success.
                run('nix', 'store', 'verify', '--store', origin, '--sigs-needed', '1', path, env=selected_reader)
                origins[path] = origin
                break
            if path not in origins:
                raise ValueError('Incomplete cache publication')
    with tempfile.TemporaryDirectory(prefix='channel-recheck-') as directory:
        reader = remote_env(env, directory)
        for path, origin in origins.items():
            actual = metadata(info([path], reader, origin).get(path))
            if actual != expected[path]:
                report_metadata_difference(path, roots, origin, expected[path], actual, recheck=True)
                raise ValueError('Publication changed during verification')
    if adopted:
        # The proof covers the cached metadata, so later audits of the cache match it.
        message = (f'Adopted {len(adopted)} existing signed cache realisation(s) whose bytes differ '
                   'from this non-reproducible build; their cached NARs were read and verified.')
        print(message, flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write(message + '\n')
    return digest({'roots': sorted(roots), 'metadata': expected})


# Promotion reads narinfo metadata only. Lookups run in parallel batches; a
# batch that contains a missing path is split until the missing path is found.
METADATA_WORKERS = 16
METADATA_BATCH = 32
SIGNATURE_BATCH = 400


def batches(values, size):
    values = sorted(values)
    return [values[index:index+size] for index in range(0, len(values), size)]


def origin_reader(reader, origin):
    """Each origin must sign its own copies with its own key and no other."""
    key = KEY if origin == CACHE else UPSTREAM_KEY
    return dict(reader, NIX_CONFIG=reader['NIX_CONFIG'] + '\ntrusted-public-keys = ' + key + '\n')


def published_metadata(paths, origin, reader):
    """Narinfo metadata the origin serves for paths; None marks a missing path."""
    def lookup(batch):
        try:
            found = info(batch, reader, origin)
        except CommandFailure as error:
            if error.category != 'missing-input-or-output':
                raise
            if len(batch) == 1:
                return {batch[0]: None}
            middle = len(batch) // 2
            return {**lookup(batch[:middle]), **lookup(batch[middle:])}
        if set(found) != set(batch):
            raise ValueError('Invalid remote metadata response')
        return {path: (None if entry is None else metadata(entry)) for path, entry in found.items()}
    result = {}
    with ThreadPoolExecutor(max_workers=METADATA_WORKERS) as pool:
        for part in pool.map(lookup, batches(paths, METADATA_BATCH)):
            result.update(part)
    return result


def verify_signatures(paths, origin, reader, **kwargs):
    """Check narinfo signatures against the origin's key without reading NARs."""
    for batch in batches(paths, SIGNATURE_BATCH):
        run('nix', 'store', 'verify', '--store', origin, '--no-contents', '--sigs-needed', '1', *batch, env=reader, **kwargs)


def verify_published(roots, expected, env):
    """Promotion gate: every closure path is published, signed and matches the build.

    Roots must be served by Niks3 with the Niks3 signature. Other paths may come
    from Niks3 (Niks3 signature) or, when Niks3 omitted them, from the official
    upstream cache (upstream signature). Metadata (narHash, narSize, references)
    must equal the build, which the signature binds. NAR bytes are not read
    here; the daily retention audit reads them. Returns the same closure digest
    as verify(), so existing proofs and audits stay comparable.
    """
    if not roots or not expected or not set(roots) <= set(expected):
        raise ValueError('Missing required output')
    if any(not STORE.fullmatch(p) or p.endswith('.drv') for p in expected):
        raise ValueError('Invalid closure path')
    expected = {p: metadata(e) for p, e in expected.items()}
    if any(ref not in expected for e in expected.values() for ref in e['references']):
        raise ValueError('Incomplete closure')
    adopted = []
    with tempfile.TemporaryDirectory(prefix='channel-metadata-') as directory:
        base = remote_env(env, directory)
        published = {}
        remaining = set(expected)
        for origin in [CACHE, UPSTREAM]:
            if not remaining:
                break
            reader = origin_reader(base, origin)
            found = published_metadata(remaining, origin, reader)
            missing = {p for p, entry in found.items() if entry is None}
            if origin == CACHE and missing & set(roots):
                raise ValueError('Required cache output is missing')
            present = set(found) - missing
            for path in sorted(present):
                actual = found[path]
                if actual != expected[path]:
                    # Same adoption rule as verify(): another publisher already
                    # holds a signed build of this input-addressed path with the
                    # same references. Its metadata enters the proof.
                    adopt = origin == CACHE and actual['references'] == expected[path]['references']
                    report_metadata_difference(path, roots, origin, expected[path], actual,
                                               action='adopted' if adopt else 'rejected')
                    if not adopt:
                        raise ValueError('Published metadata differs from build')
                    expected[path] = actual
                    adopted.append(path)
            if present:
                verify_signatures(present, origin, reader)
            published.update({p: origin for p in present})
            remaining = missing
        if remaining:
            raise ValueError('Incomplete cache publication')
    counts = {name: sum(1 for o in published.values() if o == origin)
              for name, origin in [('niks3', CACHE), ('upstream', UPSTREAM)]}
    message = ('Verified signed narinfo metadata for ' + str(len(published)) + ' closure paths ('
               + str(counts['niks3']) + ' Niks3, ' + str(counts['upstream']) + ' upstream); NAR bytes are '
               'audited by the scheduled retention run.')
    if adopted:
        message += (f' Adopted {len(adopted)} existing signed cache realisation(s) whose metadata '
                    'differs from this non-reproducible build.')
    print(message, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(message + '\n')
    return digest({'roots': sorted(roots), 'metadata': expected})


def remote_closure(roots, env):
    """Discover signed remote metadata without realising or building outputs."""
    expected = {}
    pending = list(roots)
    with tempfile.TemporaryDirectory(prefix='channel-closure-') as directory:
        reader = remote_env(env, directory)
        while pending:
            path = pending.pop()
            if path in expected:
                continue
            if not STORE.fullmatch(path):
                raise ValueError('Invalid remote reference')
            for origin in ([CACHE] if path in roots else [CACHE, UPSTREAM]):
                try:
                    entry = info([path], reader, origin).get(path)
                except RuntimeError:
                    if path in roots or origin == UPSTREAM:
                        raise
                    continue
                if entry is not None:
                    expected[path] = metadata(entry)
                    pending.extend(expected[path]['references'])
                    break
            if path not in expected:
                raise ValueError('Required cache output is missing; source builds are disabled')
    return expected


def archived_manifest(directory, rules, sha, system, record, roots):
    """Validate data-only historical variants against the original immutable proof."""
    directory = Path(directory)
    manifest = directory / 'manifest.json'
    if (manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 32*1024*1024):
        raise ValueError('Invalid retained archive manifest')
    value = json.loads(manifest.read_text())
    if (value.get('version') != 1 or value.get('commit') != sha
            or value.get('policy') != digest(rules) or value.get('system') != system
            or value.get('roots') != sorted(roots)):
        raise ValueError('Retained archive source/policy/roots differ')
    raw = value.get('metadata')
    if not isinstance(raw, dict) or not raw or len(raw) > 50000:
        raise ValueError('Invalid retained archive metadata')
    if any(not isinstance(p, str) or not STORE.fullmatch(p) or p.endswith('.drv') for p in raw):
        raise ValueError('Invalid retained archive store path')
    expected = {p: metadata(e) for p, e in raw.items()}
    if (not set(roots) <= set(expected)
            or any(ref not in expected for e in expected.values() for ref in e['references'])):
        raise ValueError('Incomplete retained archive closure')
    closure = digest({'roots': sorted(roots), 'metadata': expected})
    proof = digest({'commit': sha, 'policy': digest(rules), 'system': system, 'closure': closure})
    if proof != record['proofs'].get(system):
        raise ValueError('Retained archive differs from original build proof')
    paths = value.get('archivedPaths')
    if (not isinstance(paths, list) or not paths or any(not isinstance(p, str) for p in paths)
            or len(paths) != len(set(paths))
            or not set(paths) <= set(expected)):
        raise ValueError('Invalid retained archive variant selection')
    cache = directory / 'cache'
    if cache.is_symlink() or not cache.is_dir():
        raise ValueError('Invalid retained archive cache')
    cache_info = cache / 'nix-cache-info'
    if (cache_info.is_symlink() or not cache_info.is_file() or cache_info.stat().st_size > 65536
            or 'StoreDir: /nix/store' not in cache_info.read_text().splitlines()):
        raise ValueError('Invalid retained archive store directory')
    names = {p.removeprefix('/nix/store/').split('-', 1)[0] + '.narinfo' for p in paths}
    if {p.name for p in cache.glob('*.narinfo')} != names:
        raise ValueError('Retained archive has unselected narinfos')
    for path in paths:
        stem = path.removeprefix('/nix/store/').split('-', 1)[0]
        narinfo = cache / (stem + '.narinfo')
        nar = cache / 'nar' / (stem + '.nar')
        if (narinfo.is_symlink() or not narinfo.is_file() or narinfo.stat().st_size > 1024*1024
                or nar.is_symlink() or not nar.is_file()
                or nar.resolve().parent != cache.resolve() / 'nar'):
            raise ValueError('Invalid retained archive payload')
        urls = [line[5:] for line in narinfo.read_text().splitlines() if line.startswith('URL: ')]
        if urls != ['nar/' + stem + '.nar']:
            raise ValueError('Retained archive NAR must stay in its data directory')
    return expected, cache.as_uri(), set(paths)


def retained_archive(rules, sha, system, record, roots, env):
    config = ROOT / 'ci/retained-archives.json'
    if not config.exists():
        return None
    if config.stat().st_size > 1024*1024:
        raise ValueError('Oversize retained archive selection')
    value = json.loads(config.read_text())
    if value.get('version') != 1 or not isinstance(value.get('releases'), dict):
        raise ValueError('Invalid retained archive selection')
    selected = value['releases'].get(sha, {})
    if not isinstance(selected, dict):
        raise ValueError('Invalid retained archive platform selection')
    path = selected.get(system)
    if path is None:
        return None
    if not isinstance(path, str) or not STORE.fullmatch(path) or path.endswith('.drv'):
        raise ValueError('Invalid retained archive store path')
    phase('read-retained-archive')
    with tempfile.TemporaryDirectory(prefix='retained-archive-read-') as directory:
        reader = remote_env(env, directory)
        # Always read the outer archive NAR, even when a previous job imported it.
        run('nix', 'store', 'verify', '--store', CACHE, '--sigs-needed', '1', path, env=reader)
        run('nix', 'copy', '--from', CACHE, path, env=reader)
    return archived_manifest(path, rules, sha, system, record, roots)


def evaluated_roots(rules, system, flake=None, expression=None, env=None):
    targets = rules['targets'][system]
    selected = ' '.join('f.' + t['attribute'] for t in targets)
    apply = 'f: builtins.concatLists (map (p: map (o: p.${o}.outPath) p.outputs) [ '+selected+' ])'
    if expression:
        args = ['--impure', '--expr', '('+apply+') ('+expression+')']
    else:
        args = ['--expr', '('+apply+') (builtins.getFlake '+json.dumps(flake)+')']
    roots = json.loads(run('nix', 'eval', '--json', *args, *FLAGS, *NO_BUILD, env=env))
    if not roots or any(not STORE.fullmatch(p) for p in roots):
        raise ValueError('Missing evaluated release outputs')
    return sorted(set(roots))


def native_check_names(flake, system, env):
    # An empty flake fragment selects its default package, not its outputs.
    expression = 'builtins.attrNames ((builtins.getFlake '+json.dumps(flake)+').checks.'+system+' or {})'
    return json.loads(run('nix', 'eval', '--json', '--expr', expression, *FLAGS, env=env))


def native_check_outputs(flake, system, env):
    """Output paths of every native check, evaluated once without building."""
    expression = ('builtins.mapAttrs (n: d: map (o: d.${o}.outPath) (d.outputs or [ "out" ])) '
                  '((builtins.getFlake '+json.dumps(flake)+').checks.'+system+' or {})')
    value = json.loads(run('nix', 'eval', '--json', '--expr', expression, *FLAGS, *NO_BUILD, env=env))
    if (not isinstance(value, dict) or any(not isinstance(v, list) or not v for v in value.values())
            or any(not isinstance(p, str) or not STORE.fullmatch(p) or p.endswith('.drv') for v in value.values() for p in v)):
        raise ValueError('Invalid native check outputs')
    return value


def distinct_checks(check_outputs, roots):
    """Checks to build: those whose outputs are not already built inventory roots.

    A flake that reuses packages as checks (`checks = self.packages // {...}`)
    would otherwise rebuild, re-upload and re-inspect every package a second
    time. The same output path is the same derivation output, already built,
    published and covered by the closure gate.
    """
    built = set(roots)
    return sorted(name for name, paths in check_outputs.items() if not set(paths) <= built)


def audit(rules, sha, system, record, env, flake=None, expression=None):
    phase('validate-retained-proof')
    if (record.get('commit') != sha or record.get('policy') != digest(rules)
            or record.get('activationAuthorized') is not False):
        raise ValueError('Release source/policy differs from immutable proof')
    phase('evaluate-retained-roots')
    roots = evaluated_roots(rules, system, flake, expression, env)
    archive = retained_archive(rules, sha, system, record, roots, env)
    phase('discover-retained-closure')
    expected = archive[0] if archive else remote_closure(roots, env)
    phase('verify-retained-cache')
    closure = (verify(roots, expected, env, archived_cache=archive[1], archived_paths=archive[2])
               if archive else verify(roots, expected, env))
    phase('compare-retained-proof')
    proof = digest({'commit': sha, 'policy': digest(rules), 'system': system, 'closure': closure})
    if record['proofs'].get(system) != proof:
        recorded = record['proofs'].get(system)
        print('Retained proof mismatch: ' + json.dumps({
            'commit': sha, 'system': system, 'rootCount': len(roots),
            'closurePathCount': len(expected), 'rootsDigest': digest(roots),
            'closureDigest': closure,
            'expectedProof': recorded if isinstance(recorded, str) and re.fullmatch(r'[a-f0-9]{64}', recorded) else 'invalid',
            'actualProof': proof,
        }, sort_keys=True), flush=True)
        raise ValueError('Cached closure differs from the original build proof')
    print('Verified exact cached release outputs without source builds for ' + system)
    return {'commit': sha, 'system': system, 'policy': digest(rules), 'proof': proof, 'roots': roots}


def release_ledger(rules):
    """Advertised channels plus three recent releases per channel; no deletion.

    Returns ({sha: immutable tag record}, {role: sha}). Roles are `tested` and
    `stable` (the advertised pointers) and `<channel>-recent-<n>` for the n-th
    newest immutable tag of that channel.
    """
    token = os.environ.get('SOURCE_TOKEN') or os.environ.get('CHANNEL_TOKEN')
    if rules['forge'] == 'forgejo' and not token:
        raise ValueError('A repository read credential is required')
    with tempfile.TemporaryDirectory(prefix='channel-ledger-') as directory:
        with build_environment(dict(os.environ, CHANNEL_TOKEN=token or 'anonymous-public-reader')):
            env = git_env(directory)
        ledger = str(Path(directory)/'ledger.git')
        run('git', 'init', '--bare', ledger)
        git = ['git', '--git-dir', ledger]
        run(*git, 'fetch', '--no-tags', rules['remote'],
            'refs/tags/tested-*:refs/tags/tested-*', 'refs/tags/stable-*:refs/tags/stable-*', env=env)
        names = run(*git, 'for-each-ref', '--sort=-creatordate', '--format=%(refname)', 'refs/tags').splitlines()
        selected = set()
        roles = {}
        for channel in ['tested', 'stable']:
            recent = [n for n in names if n.startswith('refs/tags/'+channel+'-')][:3]
            selected.update(recent)
            for number, name in enumerate(recent, 1):
                roles[channel+'-recent-'+str(number)] = name.rsplit('-', 1)[-1]
            pointer = run('git', '-c', 'credential.helper=', 'ls-remote', rules['remote'], 'refs/heads/'+channel, env=env)
            if pointer:
                selected.add('refs/tags/'+channel+'-'+pointer.split()[0])
                roles[channel] = pointer.split()[0]
        result = {}
        for name in sorted(selected):
            sha = name.rsplit('-', 1)[-1]
            if not SHA.fullmatch(sha) or run(*git, 'rev-parse', name+'^{}') != sha:
                raise ValueError('Immutable release tag points at the wrong revision')
            raw = run(*git, 'cat-file', 'tag', name)
            record = json.loads(raw.split('\n\n', 1)[1])
            result[sha] = record
        if any(sha not in result for sha in roles.values()):
            raise ValueError('Advertised channel has no immutable release tag')
        return result, roles


def release_refs(rules):
    return release_ledger(rules)[0]


# Niks3 garbage-collects closures that were not pushed within its retention
# window unless a pin names them. Each release records one small manifest per
# system whose references are exactly its roots. Pins are upserted, never
# deleted, under fixed role names, so the pinned set stays bounded: the
# candidate being built plus the advertised and recent recovery releases.
MANIFEST = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-release-roots')
PIN_ROLES = ['tested', 'stable'] + [c + '-recent-' + str(n) for c in ['tested', 'stable'] for n in (1, 2, 3)]


def pin_name(rules, system, role):
    if role not in PIN_ROLES + ['candidate'] or system not in {'x86_64-linux', 'aarch64-linux', 'aarch64-darwin', 'x86_64-darwin'}:
        raise ValueError('Invalid retention pin')
    return rules['repository'].replace('/', '-') + '.' + system + '.' + role


def release_manifest(roots, env):
    """A store path whose references are the release roots; nothing is built."""
    if not roots or any(not STORE.fullmatch(p) or p.endswith('.drv') for p in roots):
        raise ValueError('Invalid release roots')
    expression = ('builtins.toFile "release-roots" (builtins.concatStringsSep "\\n" '
                  '(map builtins.storePath (builtins.fromJSON ' + json.dumps(json.dumps(sorted(roots))) + ')) + "\\n")')
    path = run('nix', 'eval', '--impure', '--raw', '--expr', expression, *NO_BUILD, env=env)
    if not MANIFEST.fullmatch(path):
        raise ValueError('Invalid release manifest')
    return path


def retention_pins(rules, system, records, roles):
    """Role pin name -> recorded manifest; releases from before manifests are skipped."""
    pins = {}
    for role, sha in sorted(roles.items()):
        manifest = (records.get(sha, {}).get('retention') or {}).get(system)
        if manifest is None:
            print('Release for retention role ' + role + ' predates retention manifests; '
                  'Niks3 keeps it only for its push-age window', flush=True)
            continue
        if not isinstance(manifest, str) or not MANIFEST.fullmatch(manifest):
            raise ValueError('Invalid recorded retention manifest')
        pins[pin_name(rules, system, role)] = manifest
    return pins


def pin_release(rules, system, roots, env, publish_env, directory):
    """Re-pin the recovery releases, then pin this candidate. Returns its manifest."""
    phase('read-release-ledgers')
    records, roles = release_ledger(rules)
    pins = retention_pins(rules, system, records, roles)
    if pins:
        phase('pin-recovery-releases')
        selection = Path(directory) / 'pins.json'
        selection.write_text(json.dumps(pins, sort_keys=True))
        run(sys.executable, str(ROOT / 'ci/push-niks3.py'), '--pins', str(selection), env=publish_env)
    phase('pin-release-candidate')
    manifest = release_manifest(roots, env)
    outputs = Path(directory) / 'manifest.txt'
    outputs.write_text(manifest + '\n')
    run(sys.executable, str(ROOT / 'ci/push-niks3.py'), '--outputs', str(outputs),
        '--pin', pin_name(rules, system, 'candidate'), env=publish_env)
    return manifest


def retain(system):
    phase('inspect-retention-policy')
    rules = policy()
    phase('read-release-ledgers')
    records = release_refs(rules)
    env = {k:v for k,v in os.environ.items() if k not in {'CHANNEL_TOKEN','SOURCE_TOKEN','GITHUB_TOKEN','GH_TOKEN'}}
    for sha, record in records.items():
        # Read-only source credential is confined to Git fetch. Historical
        # helper programs are never executed; Nix only evaluates their flake.
        with tempfile.TemporaryDirectory(prefix='retained-source-') as directory:
            token = os.environ.get('SOURCE_TOKEN') or 'anonymous-public-reader'
            with build_environment(dict(os.environ, CHANNEL_TOKEN=token)):
                reader = git_env(directory)
            tree = str(Path(directory)/'source')
            phase('fetch-retained-source')
            run('git', 'init', tree)
            run('git', '-C', tree, 'fetch', rules['remote'], sha, env=reader)
            run('git', '-C', tree, 'checkout', '--detach', 'FETCH_HEAD')
            phase('inspect-retained-policy')
            historical = json.loads((Path(tree)/'ci/channels.json').read_text())
            flake = 'git+file://'+tree+'?rev='+sha
            if historical.get('submodules'):
                phase('fetch-retained-submodules')
                run('git', '-C', tree, 'submodule', 'update', '--init', '--recursive', env=reader)
                flake += '&submodules=1'
            if system in historical['targets']:
                audit(historical, sha, system, record, env, flake=flake)
    phase('complete-retention')
    print('Cache retention verified for ' + str(len(records)) + ' advertised/recent source revisions')


def source():
    sha = run('git', 'rev-parse', 'HEAD')
    if not SHA.fullmatch(sha) or run('git', 'status', '--porcelain', '--untracked-files=no'):
        print('Tracked files that differ from the release commit: ' + (', '.join(dirty_tracked_paths()) or '(none listed)'),
              file=sys.stderr)
        raise ValueError('Release source changed')
    return sha


def native_build_ready(rules, system, env):
    if rules.get('forge') != 'forgejo' or not system.endswith('-darwin'):
        return
    native_build_admission(env)


def native_build_admission(env):
    checker = env.get('NATIVE_BUILD_ADMISSION_COMMAND', '')
    if not re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+(?:/[^\s]+)?', checker) or not os.access(checker, os.X_OK):
        raise ValueError('Missing trusted native Darwin build admission command')
    result = subprocess.run([checker], env=env, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError('Native Darwin build readiness gate rejected new work')


def native_platform_ready(rules, system, env):
    actual = run('nix', 'eval', '--impure', '--raw', '--expr', 'builtins.currentSystem', env=env)
    if actual == system:
        return
    # A private ARM Mac runner may explicitly advertise its verified Rosetta
    # capability. Do not generalize this to arbitrary cross-platform builders.
    if (rules.get('forge') != 'forgejo' or actual != 'aarch64-darwin'
            or system != 'x86_64-darwin'
            or system not in env.get('NATIVE_BUILD_COMPATIBLE_SYSTEMS', '').split()):
        raise ValueError('Native builder required')
    native_build_ready(rules, system, env)
    settings = json.loads(run('nix', 'config', 'show', '--json', env=env))
    platforms = settings.get('extra-platforms', {}).get('value', [])
    if not isinstance(platforms, list) or system not in platforms:
        raise ValueError('Intel Darwin compatibility is not configured in Nix')
    run('/usr/bin/arch', '-x86_64', '/usr/bin/true', env=env)


def derivation_output_paths(target, env):
    document = json.loads(run('nix', 'derivation', 'show', '--recursive', target, *FLAGS, env=env))
    graph = document.get('derivations', document) if isinstance(document, dict) else None
    if not isinstance(graph, dict) or not graph:
        raise ValueError('Missing build dependency graph')
    version = document.get('version') if 'derivations' in document else None
    if version is not None and version not in (1, 2, 3, 4):
        raise ValueError('Unknown derivation graph version')
    def store_path(path):
        if isinstance(path, str) and version == 4 and not path.startswith('/'):
            return '/nix/store/' + path
        return path
    paths = set()
    fixed_outputs = set()
    for drv, entry in graph.items():
        drv = store_path(drv)
        if not STORE.fullmatch(drv) or not drv.endswith('.drv') or not isinstance(entry, dict):
            raise ValueError('Invalid build dependency graph')
        outputs = entry.get('outputs')
        if not isinstance(outputs, dict) or not outputs:
            raise ValueError('Missing derivation outputs')
        for output in outputs.values():
            path = store_path(output.get('path')) if isinstance(output, dict) else None
            # JSON v4 omits computable fixed-output paths. Let Nix resolve
            # those identities rather than reimplementing its hash algorithm.
            if path is None and isinstance(output, dict) and isinstance(output.get('hash'), str) and output['hash']:
                fixed_outputs.add(drv)
                continue
            # Floating content-addressed identities need a separate resolver;
            # silently omitting them would claim incomplete coverage.
            if not isinstance(path, str) or not STORE.fullmatch(path) or path.endswith('.drv'):
                raise ValueError('Unresolved build dependency output')
            paths.add(path)
    fixed_outputs = sorted(fixed_outputs)
    for index in range(0, len(fixed_outputs), 128):
        resolved = run('nix-store', '--query', '--outputs', *fixed_outputs[index:index+128], env=env).splitlines()
        if not resolved or any(not STORE.fullmatch(path) or path.endswith('.drv') for path in resolved):
            raise ValueError('Unresolved fixed build dependency output')
        paths.update(resolved)
    return paths


PUBLIC_PROBE_SECONDS = 60
PUBLIC_ORIGIN_FAILURES = 8
PUBLIC_ORIGIN_WORKERS = 12
NAR_COMPRESSION_MAGIC = {'zstd': b'\x28', 'xz': b'\xfd', 'bzip2': b'B', 'none': b'\x0d'}


def probe_time_left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def same_public_origin(url, origin):
    target = urlsplit(url)
    return target.scheme == 'https' and target.netloc.lower() == urlsplit(origin).netloc.lower()


class PublicCacheRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        # urllib drains followed redirect bodies without a byte limit.
        return None


class NarProbeMiss(Exception):
    """The cache did not provide usable evidence that the NAR is available."""


def public_narinfo(origin, key, path, deadline):
    """Return unchanged narinfo bytes, or None for a narinfo miss."""
    base = origin.rstrip('/') + '/'
    name = path.removeprefix('/nix/store/')[:32] + '.narinfo'
    open_public = build_opener(PublicCacheRedirect()).open
    headers = {'Cache-Control': 'no-cache', 'User-Agent': 'dave-fork-ci/1'}
    checking_nar = False
    try:
        with open_public(Request(base + name, headers=headers), timeout=min(5, probe_time_left(deadline))) as response:
            if response.status != 200 or not same_public_origin(response.url, origin):
                return None
            data = response.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            return None
        lines = data.decode().split('\n')
        if [line for line in lines if line.startswith('StorePath:')] != ['StorePath: ' + path]:
            return None
        urls = [line for line in lines if line.startswith('URL:')]
        prefix = 'Sig: ' + key.split(':', 1)[0] + ':'
        if (len(urls) != 1 or not re.fullmatch(r'URL: [!-~]+', urls[0]) or '\\' in urls[0]
                or not any(line.startswith(prefix) for line in lines)):
            return None
        sizes = [line for line in lines if line.startswith('FileSize:')]
        magic = None
        if sizes:
            if len(sizes) != 1 or not re.fullmatch(r'FileSize: [1-9][0-9]*', sizes[0]):
                raise NarProbeMiss
            expected_total = sizes[0].removeprefix('FileSize: ')
        else:
            compression = [line.removeprefix('Compression: ') for line in lines if line.startswith('Compression:')]
            if len(compression) != 1 or compression[0] not in NAR_COMPRESSION_MAGIC:
                raise NarProbeMiss
            magic = NAR_COMPRESSION_MAGIC[compression[0]]
            expected_total = r'[1-9][0-9]*'
        expected_range = 'bytes 0-0/' + expected_total
        # Check that a ranged GET can read the matching NAR from the same cache.
        nar = urljoin(base, urls[0][5:])
        if not same_public_origin(nar, origin):
            raise NarProbeMiss
        checking_nar = True
        with open_public(Request(nar, headers=dict(headers, Range='bytes=0-0')),
                         timeout=min(5, probe_time_left(deadline))) as response:
            if (response.status != 206 or not same_public_origin(response.url, origin)
                    or not re.fullmatch(expected_range, response.headers.get('Content-Range', ''))
                    or response.headers.get('Content-Length', '1') != '1'):
                raise NarProbeMiss
            first_byte = response.read(1)
            if len(first_byte) != 1 or (magic is not None and first_byte != magic):
                raise NarProbeMiss
        return data
    except HTTPError as error:
        error.close()
        if ((checking_nar and error.code == 404) or error.code in {401, 403, 408, 429}
                or 500 <= error.code < 600):
            raise OSError('public cache unavailable') from None
        if checking_nar:
            raise NarProbeMiss from None
        return None
    except ValueError:
        return None


def probe_public_caches(work, deadline):
    pending = {}
    results = SimpleQueue()
    failures = {}
    active = {}
    available = Condition()
    for item in work:
        pending.setdefault(item[0], []).append(item)

    def probe():
        while True:
            with available:
                while pending and time.monotonic() < deadline:
                    origin = next((url for url in pending if active.get(url, 0) < PUBLIC_ORIGIN_WORKERS), None)
                    if origin is not None:
                        break
                    available.wait(timeout=max(0, deadline - time.monotonic()))
                else:
                    return
                items = pending[origin]
                item = items.pop()
                if not items:
                    del pending[origin]
                    if not pending:
                        available.notify_all()
                if failures.get(origin, 0) >= PUBLIC_ORIGIN_FAILURES:
                    results.put((item, None, 'cutoff'))
                    continue
                active[origin] = active.get(origin, 0) + 1
            narinfo = reason = None
            try:
                narinfo = public_narinfo(*item, deadline)
            except NarProbeMiss:
                reason = 'nar-miss'
            except (OSError, HTTPException):
                reason = 'unavailable'
            finally:
                with available:
                    if reason == 'unavailable':
                        failures[origin] = failures.get(origin, 0) + 1
                    elif failures.get(origin, 0) < PUBLIC_ORIGIN_FAILURES:
                        failures[origin] = 0
                    active[origin] -= 1
                    available.notify()
            results.put((item, narinfo, reason))

    # DNS and slow reads can outlive socket timeouts. Only the caller stages
    # results, and it never joins workers or waits past the shared deadline.
    for _ in range(min(METADATA_WORKERS, len(work))):
        Thread(target=probe, daemon=True).start()
    for _ in work:
        try:
            item, narinfo, reason = results.get(timeout=probe_time_left(deadline))
        except (Empty, TimeoutError):
            return
        if time.monotonic() >= deadline:
            return
        yield item, narinfo, reason


def served_build_outputs(entries, env):
    """Prove availability with bounded, read-only probes and Nix signature checks."""
    caches = module('cache-config.py').PUBLIC_CACHES
    work = set()
    for path, entry in entries.items():
        if entry.get('ultimate') is True or not set(entry['references']) <= entries.keys():
            # A reference outside this inventory could otherwise lose its only
            # copy. Keep this root and its recursive closure in the transfer.
            continue
        names = {sig.partition(':')[0] for sig in entry.get('signatures', []) if ':' in sig}
        # Recorded signers only schedule probes. They never prove availability.
        work.update((origin, key, path) for origin, key in caches.items() if key.split(':', 1)[0] in names)
    if not caches and entries:
        print(f'Public-cache probing unavailable; kept {len(entries)} paths.', file=sys.stderr, flush=True)
    if not work:
        return set()

    served = set()
    overdue = set()
    unavailable = set()
    cutoff = set()
    nar_misses = set()
    remaining = work.copy()
    deadline = time.monotonic() + PUBLIC_PROBE_SECONDS
    # Reserve time to verify responses even when one origin hangs.
    network_deadline = deadline - PUBLIC_PROBE_SECONDS / 5
    with tempfile.TemporaryDirectory(prefix='public-build-cache-') as directory:
        staged = {}
        for item, narinfo, reason in probe_public_caches(work, network_deadline):
            remaining.remove(item)
            origin, key, path = item
            if reason == 'cutoff':
                cutoff.add(path)
            elif reason == 'unavailable':
                unavailable.add(path)
            elif reason == 'nar-miss':
                nar_misses.add(path)
            if narinfo is None:
                continue
            if origin not in staged:
                cache = Path(directory) / str(len(staged))
                cache.mkdir()
                (cache / 'nix-cache-info').write_text('StoreDir: /nix/store\n')
                staged[origin] = (cache, key, [])
            cache, _, paths = staged[origin]
            (cache / (path.removeprefix('/nix/store/')[:32] + '.narinfo')).write_bytes(narinfo)
            paths.append(path)
        # Nix reads the exact wire bytes. Content addressing can bypass Nix's
        # signature requirement, so conservatively retain CA records.
        for cache, key, paths in staged.values():
            reader = remote_env(env, directory)
            reader['NIX_CONFIG'] += '\nsecret-key-files =\ntrusted-public-keys = ' + key + '\n'
            for batch in batches(paths, METADATA_BATCH):
                try:
                    found = info(batch, reader, cache.as_uri(), deadline=deadline)
                    matching = [path for path in batch if found.get(path) is not None
                                and not found[path].get('ca')
                                and metadata(found[path]) == metadata(entries[path])]
                    if matching:
                        verify_signatures(matching, cache.as_uri(), reader, deadline=deadline)
                        served.update(matching)
                except TimeoutError:
                    overdue.update(batch)
                except (CommandFailure, OSError, ValueError):
                    # An unverified batch stays eligible for publication.
                    continue
    overdue.update(path for _, _, path in remaining)
    limited = (overdue | cutoff) - served
    if limited:
        print(f'Public-cache probe deadline or origin cutoff reached; kept {len(limited)} paths.',
              file=sys.stderr, flush=True)
    failed = (unavailable | cutoff | overdue) - served
    if failed:
        print(f'Public-cache probing unavailable or incomplete; kept {len(failed)} paths.',
              file=sys.stderr, flush=True)
    nar_kept = nar_misses - served
    if nar_kept:
        print(f'Public NAR probe failed; kept {len(nar_kept)} paths.', file=sys.stderr, flush=True)
    return served


def completed_build_outputs(candidates, env):
    # Query only graph candidates in the local daemon. Invalid paths are null
    # in the pinned Nix JSON API; no graph output is realized or substituted.
    entries = {}
    for batch in batches(candidates, 128):
        document = json.loads(run('nix', 'path-info', '--json',
                                  '--option', 'substituters', '', '--option', 'extra-substituters', '',
                                  *batch, env=env))
        if isinstance(document, list):
            document = {entry['path']: entry for entry in document if entry is not None}
        if not isinstance(document, dict) or set(document) - set(batch):
            raise ValueError('Invalid local output inventory')
        for path, entry in document.items():
            if entry is None:
                continue
            metadata(entry)
            signatures = entry.get('signatures', [])
            if not isinstance(signatures, list) or any(not isinstance(sig, str) for sig in signatures):
                raise ValueError('Invalid output signatures')
            entries[path] = entry
    served = served_build_outputs(entries, env)
    if served:
        print(f'Public caches serve {len(served)} completed dependency outputs', file=sys.stderr, flush=True)
    return sorted(entries.keys() - served)


def build_with_dependencies(attr, rules, system, visibility, env, publish_env, outputs, label):
    candidates = derivation_output_paths(attr, env)
    native_build_ready(rules, system, env)
    phase(label)
    successful_outputs = []
    try:
        successful_outputs = run('nix', 'build', attr + '^*', *FLAGS, '--fallback', '--no-link',
                                 '--print-out-paths', env=env).splitlines()
        return successful_outputs
    finally:
        # A failed later derivation does not invalidate completed vendor,
        # compiler or check dependencies. Publish only valid outputs from this
        # selected graph, never arbitrary paths in a shared builder's store.
        paths = completed_build_outputs(candidates - set(successful_outputs), env)
        if paths:
            closure = info(paths, env)
            if rules['forge'] == 'github':
                if visibility == 'cache-only':
                    module('build-cache-only.py').check(list(closure))
                else:
                    module('public-closure.py').check_paths(list(closure))
            outputs.write_text('\n'.join(paths) + '\n')
            phase('upload-completed-build-dependencies')
            run(sys.executable, str(ROOT / 'ci/push-niks3.py'), '--outputs', str(outputs), env=publish_env)


def build(system):
    rules = policy()
    if rules.get('kind') == 'fleet':
        raise ValueError('Fleet releases require the existing exact-release verifier')
    sha = source()
    PROGRESS.update(system=system, sha=sha)
    progress('starting', force=True)
    # Writer/forge tokens never enter Nix evaluation or package build processes.
    env = {k: v for k, v in os.environ.items()
           if k not in {'CHANNEL_TOKEN', 'SOURCE_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'STATUS_TOKEN', 'NIKS3_WRITE_TOKEN', 'NIKS3_AUTH_TOKEN_FILE', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL'}}
    phase('check-native-platform')
    native_platform_ready(rules, system, env)
    targets = rules['targets'][system]
    # Preserve Git self.rev/lastModified, and exclude checkout submodules and
    # untracked CI files just as the consuming git flake does.
    flake = 'git+file://' + str(ROOT) + '?rev=' + sha
    if rules.get('submodules'):
        flake += '&submodules=1'
    phase('evaluate-system-inventory')
    systems = json.loads(run('nix', 'eval', '--json', flake + '#packages', '--apply',
                             'builtins.attrNames', *FLAGS, env=env))
    if set(systems) - set(rules.get('excludedSystems', [])) != set(rules['targets']):
        raise ValueError('Channel policy omits a supported system')
    roots = []
    expected = {}
    with tempfile.TemporaryDirectory(prefix='channel-outputs-') as directory:
        phase('prepare-cache-publisher')
        publish_env = {k: v for k, v in os.environ.items() if k != 'STATUS_TOKEN'}
        outputs = Path(directory) / 'outputs.txt'
        for index, target in enumerate(targets, 1):
            print(f'Processing inventory target {index}/{len(targets)}', flush=True)
            progress(f'target {index}/{len(targets)} ' + target['attribute'].rsplit('.', 1)[-1],
                     force=index in (1, len(targets)))
            attr = flake + '#' + target['attribute']
            phase('inspect-output-policy')
            if target['visibility'] == 'public':
                with build_environment(env):
                    module('public-closure.py').derivation(attr)
            elif target['visibility'] == 'cache-only':
                # Reuse the recursive, on-prem-only source exclusion policy.
                guard = module('build-cache-only.py')
                graph = json.loads(run('nix', 'derivation', 'show', '--recursive', attr, *FLAGS, env=env))
                guard.check(graph)
            paths = build_with_dependencies(attr, rules, system, target['visibility'], env,
                                            publish_env, outputs, 'build-required-output')
            if not paths or any(not STORE.fullmatch(p) or p.endswith('.drv') for p in paths):
                raise ValueError('Missing built outputs')
            target_closure = info(paths, env)
            if rules['forge'] == 'github':
                if target['visibility'] == 'public':
                    module('public-closure.py').check_paths(list(target_closure))
                elif target['visibility'] == 'cache-only':
                    module('build-cache-only.py').check(list(target_closure))
            for path, entry in target_closure.items():
                if path in expected and metadata(expected[path]) != metadata(entry):
                    raise ValueError('Inconsistent local closure metadata')
                expected[path] = entry
            # Keep completed closures as substitutes if a later target or
            # native check fails. Channel promotion still requires the full
            # inventory, checks and independent cache verification below.
            outputs.write_text('\n'.join(paths) + '\n')
            phase('upload-target-closure')
            run(sys.executable, str(ROOT / 'ci/push-niks3.py'), '--outputs', str(outputs), env=publish_env)
            roots.extend(paths)
            print(f'Built and cached inventory target {index}/{len(targets)}', flush=True)
        # All native flake checks are required, even when the package job would
        # otherwise reuse a cached output. Missing checks are an empty set.
        phase('build-native-checks')
        checks = native_check_names(flake, system, env)
        if any(not re.fullmatch(r'[\w+-]+', name) for name in checks):
            raise ValueError('Invalid check name')
        check_outputs = native_check_outputs(flake, system, env)
        if set(check_outputs) != set(checks):
            raise ValueError('Native check inventory changed during evaluation')
        distinct = distinct_checks(check_outputs, roots)
        print(f'Building {len(distinct)} of {len(checks)} native checks; the other '
              f'{len(checks) - len(distinct)} are inventory outputs already built and published', flush=True)
        progress(f'checks 0/{len(distinct)} ({len(checks) - len(distinct)} are inventory outputs)', force=True)
        for number, name in enumerate(distinct, 1):
            native_build_ready(rules, system, env)
            progress(f'checks {number}/{len(distinct)} ' + name, force=number == len(distinct))
            check_attr = flake + '#checks.' + system + '.' + name
            check_visibility = 'cache-only' if all(t['visibility'] == 'cache-only' for t in targets) else 'public'
            if rules['forge'] == 'github':
                with build_environment(env):
                    if check_visibility == 'cache-only':
                        module('build-cache-only.py').check(json.loads(run('nix', 'derivation', 'show', '--recursive', check_attr, *FLAGS, env=env)))
                    else:
                        module('public-closure.py').derivation(check_attr)
            check_paths = build_with_dependencies(check_attr, rules, system, check_visibility, env,
                                                  publish_env, outputs, 'build-native-check')
            if not check_paths or any(not STORE.fullmatch(p) or p.endswith('.drv') for p in check_paths):
                raise ValueError('Missing native check outputs')
            # Checks can be expensive build-only outputs. Cache each completed
            # check even if a later check or release verification fails.
            outputs.write_text('\n'.join(check_paths) + '\n')
            phase('upload-check-closure')
            run(sys.executable, str(ROOT / 'ci/push-niks3.py'), '--outputs', str(outputs), env=publish_env)
        roots = sorted(set(roots))
        phase('inspect-built-closure')
        if not roots or not expected or not set(roots) <= set(expected):
            raise ValueError('Missing built output closure')
        phase('verify-published-metadata')
        progress(f'verifying signed metadata for {len(expected)} closure paths', force=True)
        proof = verify_published(roots, expected, env)
        progress('pinning release closures', force=True)
        manifest = pin_release(rules, system, roots, env, publish_env, directory)
        phase('record-release-proof')
        if source() != sha:
            raise ValueError('Source changed during release')
        receipt = digest({'commit': sha, 'policy': digest(rules), 'system': system, 'closure': proof})
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('proof=' + receipt + '\nretention=' + manifest + '\n')
        print('Required builds, checks, upload and signed cache metadata passed for ' + system)
        progress('passed: ' + str(len(targets)) + ' targets, ' + str(len(distinct)) + ' distinct checks, '
                 + str(len(expected)) + ' signed closure paths', state='success')


def git_env(directory):
    token = os.environ.get('CHANNEL_TOKEN', '')
    if not token or any(c.isspace() for c in token):
        raise ValueError('Missing channel writer')
    askpass = Path(directory) / 'askpass'
    askpass.write_text('#!/bin/sh\ncase "$1" in *Username*) echo x-access-token;; *) printf "%s\\n" "$CHANNEL_TOKEN";; esac\n')
    askpass.chmod(0o700)
    # The private-input reader is pull-only and must not shadow this narrowly
    # scoped writer. Never borrow desktop/global Git credentials for promotion.
    return dict(os.environ, GIT_ASKPASS=str(askpass), GIT_TERMINAL_PROMPT='0',
                GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')


def promote(channel, revision, proofs, retention=None):
    rules = policy()
    if channel not in {'tested', 'stable'} or not SHA.fullmatch(revision):
        raise ValueError('Invalid release selection')
    if set(proofs) != (set(rules['targets']) | set(rules.get('cacheOnlySystems', []))) or any(not re.fullmatch(r'[a-f0-9]{64}', p) for p in proofs.values()):
        raise ValueError('Missing required system proof')
    # Retention manifests are recorded so later builds can keep this release
    # pinned in Niks3 while it is advertised or in the recent recovery set.
    retention = {k: v for k, v in (retention or {}).items() if v}
    if not set(retention) <= set(proofs) or any(not isinstance(v, str) or not MANIFEST.fullmatch(v) for v in retention.values()):
        raise ValueError('Invalid retention manifest')
    url = rules['remote']
    if url not in {'https://github.com/' + rules['repository'] + '.git',
                   'https://git.monke.fail/' + rules['repository'] + '.git'}:
        raise ValueError('Unreviewed forge destination')
    with tempfile.TemporaryDirectory(prefix='channel-git-') as directory:
        env = git_env(directory)
        args = ['git', '-c', 'credential.helper=']
        run(*args, 'fetch', '--no-tags', url, '+refs/heads/' + rules['branch'] + ':refs/remotes/channel/source', env=env)
        latest = run('git', 'rev-parse', 'refs/remotes/channel/source')
        if channel == 'tested' and latest != revision:
            print('Source branch advanced; this candidate will not move tested')
            return
        if channel == 'stable':
            run(*args, 'fetch', '--no-tags', url, 'refs/tags/tested-' + revision, env=env)
            if run('git', 'rev-parse', 'FETCH_HEAD^{}') != revision:
                raise ValueError('Stable requires an immutable tested release')
        # Normal non-forced branch updates provide an ancestry/race check on the
        # server. Both immutable tag and channel move together or neither does.
        tag = channel + '-' + revision
        record = {'version': 1, 'commit': revision, 'policy': digest(rules),
                  'proofs': proofs, 'activationAuthorized': False}
        if retention:
            record['retention'] = retention
        message = json.dumps(record, sort_keys=True)
        existing = run(*args, 'ls-remote', url, 'refs/tags/' + tag + '^{}', env=env)
        if existing:
            if existing.split()[0] != revision:
                raise ValueError('Immutable release tag collision')
            run(*args, 'push', url, revision + ':refs/heads/' + channel, env=env)
        else:
            run('git', '-c', 'user.name=Release channel', '-c', 'user.email=release-channel@monke.fail',
                'tag', '-a', tag, revision, '-m', message)
            run(*args, 'push', '--atomic', url, 'refs/tags/' + tag, revision + ':refs/heads/' + channel, env=env)
        print('Published ' + channel + ' at ' + revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'promote', 'policy', 'retain', 'daemon'])
    parser.add_argument('--system')
    parser.add_argument('--channel', choices=['tested', 'stable'], default='tested')
    parser.add_argument('--revision')
    parser.add_argument('--proofs', default='{}')
    parser.add_argument('--retention', default='{}')
    args = parser.parse_args()
    try:
        if args.action == 'daemon':
            ensure_daemon()
        elif args.action == 'build':
            ensure_daemon()
            build(args.system)
        elif args.action == 'promote':
            promote(args.channel, args.revision, json.loads(args.proofs), json.loads(args.retention))
        elif args.action == 'retain':
            ensure_daemon()
            retain(args.system)
        else:
            print(json.dumps(policy(), sort_keys=True))
    except CommandFailure as error:
        print('Release channel gate failed during ' + ACTIVE_PHASE + ': ' + str(error) + '; the previous channel is retained.', file=sys.stderr)
        progress('failed during ' + ACTIVE_PHASE + ': ' + (error.category or 'command-failed'), state='failure')
        return 1
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        kind = failure_category(str(error))
        if kind == 'command-failed': kind = 'validation-failed'
        print('Release channel gate failed during ' + ACTIVE_PHASE + ': ' + kind + '; the previous channel is retained.', file=sys.stderr)
        progress('failed during ' + ACTIVE_PHASE + ': ' + kind, state='failure')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
