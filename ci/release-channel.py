#!/usr/bin/env python3
"""Build, publish, independently read, then advance immutable source channels.

Managed source: dave-fork-ci/ci/release-channel.py. No activation or deletion.
Only the promote command has forge write credentials.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ATTIC = 'https://attic.monke.fail'
# The Attic host's address on the Forgejo runner network, reachable only from
# jobs on the icicle-hosted `nix` runner. It serves the same cache and keys.
INTERNAL_ATTIC = 'http://172.29.0.1:8080'
# The same listener over the tailnet, for the host-mode braco runner.
TAILNET_ATTIC = 'http://icicle.eel-ling.ts.net:8080'
REVIEWED_ATTIC = {PUBLIC_ATTIC, INTERNAL_ATTIC, TAILNET_ATTIC}
PUBLIC_CACHE = PUBLIC_ATTIC + '/flakey'


def attic_server(environ=None):
    """Origin used to read the cache; the public one unless the job opts in.

    Only the three reviewed origins are accepted, so a credential can reach plain
    HTTP only at the private runner-network or tailnet address of the Attic host. Proofs and records never
    store the transport; PUBLIC_CACHE is the one canonical cache identity.
    """
    value = (os.environ if environ is None else environ).get('ATTIC_SERVER', '').strip().rstrip('/')
    if value and value not in REVIEWED_ATTIC:
        raise ValueError('ATTIC_SERVER is not a reviewed Attic origin')
    return value or PUBLIC_ATTIC


try:
    CACHE = attic_server() + '/flakey'
except ValueError as error:
    sys.exit('Release channel gate failed during startup: ' + str(error) + '.')
KEY = 'flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8='
UPSTREAM = 'https://cache.nixos.org'
UPSTREAM_KEY = 'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='
STORE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+')
SHA = re.compile(r'[a-f0-9]{40}')
FLAGS = ['--option', 'accept-flake-config', 'false', '--no-update-lock-file', '--no-write-lock-file']
NO_BUILD = ['--option', 'max-jobs', '0', '--option', 'builders', '', '--option', 'fallback', 'false']


ACTIVE_PHASE = 'startup'


def phase(label):
    global ACTIVE_PHASE
    if not re.fullmatch(r'[a-z-]+', label):
        raise ValueError('Invalid release phase')
    ACTIVE_PHASE = label
    print('Release phase: ' + label, flush=True)


class CommandFailure(RuntimeError):
    """A fixed diagnostic category, never raw subprocess output or arguments."""


def failure_category(diagnostic):
    patterns = [
        ('source-hash-mismatch', r'hash mismatch in fixed-output derivation'),
        ('cache-integrity', r'nar.*hash mismatch|corrupted path|invalid nar'),
        ('cache-metadata-mismatch', r'published metadata differs|publication changed'),
        ('cache-missing-output', r'incomplete cache publication|required cache output is missing'),
        ('cache-signature', r'lacks a signature|is not signed|invalid signature|no trusted signature'),
        ('authorization', r'HTTP[^\n]*(?:401|403)|unauthorized|forbidden|authentication failed'),
        ('transport', r'unexpected eof|http/2|framing|connection reset|timed out|timeout|internalservererror|HTTP[^\n]*50[0-9]'),
        ('missing-input-or-output', r'HTTP[^\n]*404|does not exist|no such file'),
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


def run(*args, env=None):
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=6*3600)
    except subprocess.TimeoutExpired:
        raise CommandFailure('command deadline exceeded') from None
    if result.returncode:
        # Nix diagnostics may contain private paths or authenticated URLs. Emit
        # the classification, the status and a redacted tail of Nix error lines.
        diagnostic = (result.stderr or '') + '\n' + (result.stdout or '')
        message = failure_category(diagnostic) + ' (exit ' + str(result.returncode) + ')'
        detail = safe_detail(diagnostic)
        raise CommandFailure(message + (': ' + detail if detail else ''))
    return result.stdout.strip()


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


def info(paths, env, store=None):
    args = ['nix', 'path-info', '--json']
    if store:
        args += ['--store', store]
    else:
        args += ['--recursive']
    value = json.loads(run(*args, *paths, env=env))
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
    detail = {'root': path in roots, 'origin': 'attic' if origin == CACHE else 'upstream',
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
                'narinfo-cache-positive-ttl = 86400\ndownload-attempts = 3\n')


def verify(roots, expected, env):
    if not roots or not expected or not set(roots) <= set(expected):
        raise ValueError('Missing required output')
    if any(not STORE.fullmatch(p) or p.endswith('.drv') for p in expected):
        raise ValueError('Invalid closure path')
    expected = {p: metadata(e) for p, e in expected.items()}
    if any(ref not in expected for e in expected.values() for ref in e['references']):
        raise ValueError('Incomplete closure')
    # Roots must come from our publisher. Dependencies can use the reviewed
    # upstream cache when Attic's upstream-signature filter omits them.
    origins = {}
    adopted = []
    with tempfile.TemporaryDirectory(prefix='channel-read-') as directory:
        reader = remote_env(env, directory)
        for path, entry in list(expected.items()):
            for origin in ([CACHE] if path in roots else [CACHE, UPSTREAM]):
                try:
                    remote = info([path], reader, origin)
                except RuntimeError:
                    if origin == UPSTREAM or path in roots:
                        raise
                    continue
                if remote.get(path) is None:
                    continue
                actual = metadata(remote[path])
                if actual != entry:
                    # Another publisher already holds a different build of this
                    # input-addressed path, and Attic keeps that first copy. A
                    # non-reproducible rebuild cannot replace it. Adopt the
                    # signed cached copy only when its references match, then
                    # read and verify its bytes like any other member. Both
                    # metadata digests are logged.
                    adopt = origin == CACHE and actual['references'] == entry['references']
                    report_metadata_difference(path, roots, origin, entry, actual,
                                               action='adopted' if adopt else 'rejected')
                    if not adopt:
                        raise ValueError('Published metadata differs from build')
                    expected[path] = actual
                    adopted.append(path)
                # Reads NAR bytes, verifies hash and signature; no --no-contents,
                # local-store fallback, source build or metadata-only success.
                run('nix', 'store', 'verify', '--store', origin, '--sigs-needed', '1', path, env=reader)
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


def audit(rules, sha, system, record, env, flake=None, expression=None):
    phase('validate-retained-proof')
    if (record.get('commit') != sha or record.get('policy') != digest(rules)
            or record.get('activationAuthorized') is not False):
        raise ValueError('Release source/policy differs from immutable proof')
    phase('evaluate-retained-roots')
    roots = evaluated_roots(rules, system, flake, expression, env)
    phase('discover-retained-closure')
    expected = remote_closure(roots, env)
    phase('verify-retained-cache')
    closure = verify(roots, expected, env)
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


def release_refs(rules):
    """Advertised channels plus three recent releases per channel; no deletion."""
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
        for channel in ['tested', 'stable']:
            selected.update([n for n in names if n.startswith('refs/tags/'+channel+'-')][:3])
            pointer = run('git', '-c', 'credential.helper=', 'ls-remote', rules['remote'], 'refs/heads/'+channel, env=env)
            if pointer:
                selected.add('refs/tags/'+channel+'-'+pointer.split()[0])
        result = {}
        for name in sorted(selected):
            sha = name.rsplit('-', 1)[-1]
            if not SHA.fullmatch(sha) or run(*git, 'rev-parse', name+'^{}') != sha:
                raise ValueError('Immutable release tag points at the wrong revision')
            raw = run(*git, 'cat-file', 'tag', name)
            record = json.loads(raw.split('\n\n', 1)[1])
            result[sha] = record
        return result


def retain(system):
    phase('inspect-retention-policy')
    rules = policy()
    phase('read-release-ledgers')
    records = release_refs(rules)
    env = {k:v for k,v in os.environ.items() if k not in {'ATTIC_TOKEN','CHANNEL_TOKEN','SOURCE_TOKEN','GITHUB_TOKEN','GH_TOKEN'}}
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
        raise ValueError('Release source changed')
    return sha


def build(system):
    rules = policy()
    if rules.get('kind') == 'fleet':
        raise ValueError('Fleet releases require the existing exact-release verifier')
    sha = source()
    # Writer/forge tokens never enter Nix evaluation or package build processes.
    env = {k: v for k, v in os.environ.items()
           if k not in {'ATTIC_TOKEN', 'CHANNEL_TOKEN', 'SOURCE_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN'}}
    phase('check-native-platform')
    if run('nix', 'eval', '--impure', '--raw', '--expr', 'builtins.currentSystem', env=env) != system:
        raise ValueError('Native builder required')
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
        client = run('nix', 'build', '--inputs-from', flake, 'nixpkgs#attic-client', *FLAGS,
                     '--no-link', '--print-out-paths', env=env)
        if not STORE.fullmatch(client):
            raise ValueError('Invalid publisher')
        publish_env = dict(os.environ, ATTIC_BIN=client + '/bin/attic',
                           ATTIC_ENDPOINT='https://attic.monke.fail', ATTIC_CACHE='flakey')
        outputs = Path(directory) / 'outputs.txt'
        for index, target in enumerate(targets, 1):
            print(f'Processing inventory target {index}/{len(targets)}', flush=True)
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
            phase('build-required-output')
            paths = run('nix', 'build', attr + '^*', *FLAGS, '--fallback', '--no-link',
                        '--print-out-paths', env=env).splitlines()
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
            run(sys.executable, str(ROOT / 'ci/push-attic.py'), '--outputs', str(outputs), env=publish_env)
            roots.extend(paths)
            print(f'Built and cached inventory target {index}/{len(targets)}', flush=True)
        # All native flake checks are required, even when the package job would
        # otherwise reuse a cached output. Missing checks are an empty set.
        phase('build-native-checks')
        checks = native_check_names(flake, system, env)
        for name in checks:
            if not re.fullmatch(r'[\w+-]+', name):
                raise ValueError('Invalid check name')
            run('nix', 'build', flake + '#checks.' + system + '.' + name, *FLAGS, '--no-link', env=env)
        roots = sorted(set(roots))
        phase('inspect-built-closure')
        if not roots or not expected or not set(roots) <= set(expected):
            raise ValueError('Missing built output closure')
        phase('verify-remote-cache')
        proof = verify(roots, expected, env)
        phase('record-release-proof')
        if source() != sha:
            raise ValueError('Source changed during release')
        receipt = digest({'commit': sha, 'policy': digest(rules), 'system': system, 'closure': proof})
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('proof=' + receipt + '\n')
        print('Required builds, checks, upload and independent cache reads passed for ' + system)


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


def promote(channel, revision, proofs):
    rules = policy()
    if channel not in {'tested', 'stable'} or not SHA.fullmatch(revision):
        raise ValueError('Invalid release selection')
    if set(proofs) != (set(rules['targets']) | set(rules.get('cacheOnlySystems', []))) or any(not re.fullmatch(r'[a-f0-9]{64}', p) for p in proofs.values()):
        raise ValueError('Missing required system proof')
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
        message = json.dumps({'version': 1, 'commit': revision, 'policy': digest(rules),
                              'proofs': proofs, 'activationAuthorized': False}, sort_keys=True)
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
    parser.add_argument('action', choices=['build', 'promote', 'policy', 'retain'])
    parser.add_argument('--system')
    parser.add_argument('--channel', choices=['tested', 'stable'], default='tested')
    parser.add_argument('--revision')
    parser.add_argument('--proofs', default='{}')
    args = parser.parse_args()
    try:
        if args.action == 'build':
            build(args.system)
        elif args.action == 'promote':
            promote(args.channel, args.revision, json.loads(args.proofs))
        elif args.action == 'retain':
            retain(args.system)
        else:
            print(json.dumps(policy(), sort_keys=True))
    except CommandFailure as error:
        print('Release channel gate failed during ' + ACTIVE_PHASE + ': ' + str(error) + '; the previous channel is retained.', file=sys.stderr)
        return 1
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        kind = failure_category(str(error))
        if kind == 'command-failed': kind = 'validation-failed'
        print('Release channel gate failed during ' + ACTIVE_PHASE + ': ' + kind + '; the previous channel is retained.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
