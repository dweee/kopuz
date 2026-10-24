#!/usr/bin/env python3
"""Report manual source/version pins and update-check failures without rewrites."""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def api_host(url, required=None):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'api.github.com', 'git.monke.fail'}
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in {None, 443} or parsed.fragment
            or (required is not None and parsed.hostname != required)):
        raise ValueError('Unreviewed monitoring endpoint')
    return parsed.hostname


def fetch(url):
    host = api_host(url)
    headers = {'User-Agent': 'release-update-monitor', 'Accept': 'application/json'}
    # Tokens are only sent to their own forge API; never source/artifact URLs.
    token = os.environ.get('GH_TOKEN', '') if host == 'api.github.com' else os.environ.get('MONITOR_TOKEN', '')
    if token:
        headers['Authorization'] = ('Bearer ' if host == 'api.github.com' else 'token ') + token
    class NoRedirect(__import__('urllib.request', fromlist=['HTTPRedirectHandler']).HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = __import__('urllib.request', fromlist=['build_opener']).build_opener(NoRedirect())
    # GitHub redirects renamed repositories to their stable repository-ID URL.
    # Validate every hop before constructing the next authenticated request.
    for hops in range(4):
        try:
            with opener.open(Request(url, headers=headers), timeout=45) as response:
                data = response.read(8*1024*1024+1)
                if len(data) > 8*1024*1024:
                    raise ValueError('Oversize release metadata')
                return json.loads(data)
        except HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            location = error.headers.get('Location')
            if not location or hops == 3:
                raise ValueError('Monitoring API redirect limit or missing target') from None
            target = urljoin(url, location)
            api_host(target, host)
            url = target


def discover(text):
    """Find explicit release asset URLs and fetchFromGitHub source blocks.

    Dynamic/unrecognized sources are listed separately, never called current.
    """
    result = []
    versions = list(re.finditer(r'\bversion\s*=\s*"([^"\n]+)"', text))
    def expand(value, position):
        earlier = [m.group(1) for m in versions if m.start() < position]
        return value.replace('${version}', earlier[-1]) if earlier else value
    for match in re.finditer(r'https://github\.com/([\w.-]+)/([\w.-]+)/releases/download/([^/"\s]+)', text):
        result.append((match[1]+'/'+match[2], expand(match[3], match.start())))
    # Bound each source fetcher block. Interpolations may contain braces, so
    # field matching stops at the next hash rather than the first closing brace.
    for match in re.finditer(r'fetchFromGitHub\s*\{(.{0,1500}?)\b(?:hash|sha256)\s*=', text, re.S):
        fields = dict(re.findall(r'\b(owner|repo|rev|tag)\s*=\s*"([^"\n]+)"', match[1]))
        ref = fields.get('tag', fields.get('rev'))
        if fields.get('owner') and fields.get('repo') and ref:
            result.append((fields['owner']+'/'+fields['repo'], expand(ref, match.start())))
    return sorted(set(result))


def raw_file_pins(text):
    pattern = r'(?:url\s*=\s*|"url"\s*:\s*)"(https://(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)/[^"\s]+)".{0,300}?(?:hash\s*=\s*|"hash"\s*:\s*)"(sha256-[A-Za-z0-9+/=]+)"'
    return [(m[1], m[2]) for m in re.finditer(pattern, text, re.S)
            if '$' not in m[1] and urlsplit(m[1]).path.endswith(('.yaml', '.yml', '.json', '.nix', '.py', '.sh', '.txt', '.toml', '.patch', '.lua', '.js'))]


def file_hash(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'raw.githubusercontent.com', 'gist.githubusercontent.com'}
            or parsed.username or parsed.query or parsed.fragment):
        raise ValueError('Unreviewed raw file endpoint')
    class NoRedirect(__import__('urllib.request', fromlist=['HTTPRedirectHandler']).HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('Raw file redirect refused')
    opener = __import__('urllib.request', fromlist=['build_opener']).build_opener(NoRedirect())
    # No auth header is sent to content hosts.
    with opener.open(Request(url, headers={'User-Agent': 'release-update-monitor'}), timeout=45) as response:
        content = response.read(5*1024*1024+1)
        if len(content) > 5*1024*1024:
            raise ValueError('Oversize monitored file')
    return 'sha256-' + base64.b64encode(hashlib.sha256(content).digest()).decode()


def scan():
    config = json.loads((ROOT / 'ci/update-monitor.json').read_text())
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    findings, unclassified, raw_pins = {}, [], []
    for name in files:
        if not name or not name.endswith(('.nix', '.json', '.toml', '.yaml', '.yml')):
            continue
        if name.startswith(('ci/', 'docs/', 'node_modules/')) or name.endswith(('flake.lock', 'package-lock.json', 'pnpm-lock.yaml')):
            continue
        if any(name == prefix or name.startswith(prefix.rstrip('/') + '/') for prefix in config.get('exclude', [])):
            continue
        path = ROOT / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 2*1024*1024:
            continue
        text = path.read_text(errors='replace')
        refs = discover(text)
        for url, checksum in raw_file_pins(text):
            raw_pins.append({'file': name, 'url': url, 'hash': checksum})
        if name.startswith(('.github/', '.forgejo/')):
            for action in re.finditer(r'uses:\s*["\']?([\w.-]+/[\w.-]+)(?:/[^@\s]+)?@([a-f0-9]{40})', text):
                findings.setdefault(action[1], []).append({'file': name, 'pin': action[2]})
        for repo, ref in refs:
            if '$' in ref or not re.fullmatch(r'[\w.+-]+', ref):
                unclassified.append(name)
            else:
                findings.setdefault(repo, []).append({'file': name, 'pin': ref})
        if re.search(r'fetchurl|fetchgit|fetchFrom|"(?:url|urls)"\s*:\s*(?:\[\s*)?"https://', text) and not refs:
            unclassified.append(name)
    report = {'version': 1, 'updates': [], 'errors': [], 'manualReview': sorted(unclassified),
              'checkedSources': [], 'customChecks': []}
    for pin in raw_pins:
        try:
            actual = file_hash(pin['url'])
            report['checkedSources'].append(pin['url'])
            if actual != pin['hash']:
                report['updates'].append({**pin, 'latestHash': actual, 'kind': 'file-content-changed'})
        except (OSError, ValueError):
            report['errors'].append({'file': pin['file'], 'error': 'raw file check failed'})
    for repo, pins in sorted(findings.items()):
        try:
            release = fetch('https://api.github.com/repos/' + repo + '/releases/latest')
            latest = release['tag_name']
            report['checkedSources'].append(repo)
            different = []
            for pin in pins:
                if pin['pin'] == latest or pin['pin'].removeprefix('v') == latest.removeprefix('v'):
                    continue
                comparison = fetch('https://api.github.com/repos/' + repo + '/compare/' + pin['pin'] + '...' + latest)
                if comparison.get('status') in {'ahead', 'diverged'}:
                    different.append(pin)
            if different:
                report['updates'].append({'repository': repo, 'latest': latest, 'pins': different})
        except HTTPError as error:
            if error.code == 404:
                report['manualReview'].extend(p['file'] for p in pins)
            else:
                report['errors'].append({'repository': repo, 'error': 'release lookup failed'})
        except (OSError, ValueError, KeyError):
            report['errors'].append({'repository': repo, 'error': 'release lookup failed'})
    # Explicit upstream monitoring also covers application forks whose sources
    # live in-tree rather than in a fetchFromGitHub expression.
    for entry in config.get('upstreams', []):
        try:
            value = fetch(entry['api'])
            latest = value.get('tag_name') or value.get('sha')
            if not latest:
                raise ValueError('No upstream revision')
            current = entry.get('current')
            if current != latest:
                report['updates'].append({'repository': entry['name'], 'latest': latest,
                                          'kind': 'upstream-review', 'current': current or 'in-tree fork'})
        except (OSError, ValueError, KeyError):
            report['errors'].append({'repository': entry['name'], 'error': 'upstream lookup failed'})
    for command in config.get('checks', []):
        before = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=ROOT)
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=3600)
            unchanged = before == subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=ROOT)
            # Do not echo updater diagnostics into public reports.
            report['customChecks'].append({'command': command, 'success': result.returncode == 0 and unchanged,
                                           'outputHash': hashlib.sha256(result.stdout.encode()).hexdigest(),
                                           'candidates': [line for line in result.stdout.splitlines()
                                                          if line.startswith(('candidate available ', 'UPDATE ', 'update available '))]})
            if result.returncode or not unchanged:
                report['errors'].append({'command': command, 'error': 'check failed or changed tracked files'})
        except (OSError, subprocess.SubprocessError):
            report['errors'].append({'command': command, 'error': 'check failed'})
    report['manualReview'] = sorted(set(report['manualReview']))
    return report


if __name__ == '__main__':
    try:
        report = scan()
        destination = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'version-monitor.json'
        destination.write_text(json.dumps(report, indent=2)+'\n')
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a') as out:
                out.write('### Manual version monitoring\n\n' + json.dumps(report, indent=2).join(['```json\n', '\n```\n']))
        print(str(len(report['updates'])) + ' source update candidates; ' + str(len(report['errors'])) + ' failed checks; '
              + str(len(report['manualReview'])) + ' files require manual review')
        sys.exit(1 if report['errors'] else 0)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Version monitor failed; no current-version claim is available.', file=sys.stderr)
        sys.exit(1)
