#!/usr/bin/env python3
"""Keep the helper-digest exception narrower than a credential exception."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def scan(directory, report):
    result = subprocess.run(
        ['gitleaks', 'dir', '--redact', '--no-banner', '--config', str(ROOT / '.gitleaks.toml'),
         '--report-format', 'json', '--report-path', str(report), '.'],
        cwd=directory, capture_output=True, text=True, timeout=30)
    if result.returncode not in (0, 1) or not report.exists():
        raise AssertionError('Secret scanner did not complete normally')
    return result.returncode, json.loads(report.read_text())


def test_policy():
    hashes = json.loads((ROOT / 'ci/channel-tool-hashes.json').read_text())
    digest = hashes['niks3-oidc-token.py']
    with tempfile.TemporaryDirectory(prefix='helper-digest-policy-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        (fixture / 'ci').mkdir(parents=True)
        manifest = fixture / 'ci/channel-tool-hashes.json'
        manifest.write_text(json.dumps({'niks3-oidc-token.py': digest}))
        status, findings = scan(fixture, root / 'allowed.json')
        assert status == 0 and not findings, 'Reviewed manifest digest was rejected'
        # A non-hex synthetic value inside the manifest and the exact digest
        # outside it must remain detectable. Neither fixture is a live secret.
        manifest.write_text(json.dumps({'niks3-oidc-token.py': digest[:-1] + 'g'}))
        (fixture / 'other.json').write_text(json.dumps({'niks3-oidc-token.py': digest}))
        status, findings = scan(fixture, root / 'rejected.json')
        assert status == 1 and len(findings) == 2, 'Digest exception is too broad'
        assert any(f['File'].endswith('ci/channel-tool-hashes.json') for f in findings)
        assert any(f['File'].endswith('other.json') for f in findings)
    print('Helper digest exception preserves credential detection.')


# Append this function to ci/test-gitleaks-config.py, then invoke it in __main__.
# It uses the existing ROOT and scan(directory, report) helper. No test was run
# by the classification leaf. It creates no real credentials or network calls.
def test_anonymous_fixture_exceptions_are_exact():
    import hashlib
    import shutil
    names = [
        'album', 'artist_singles', 'charts', 'episode', 'explore',
        'home_continuation', 'next_counterpart', 'next_radio', 'playlist',
        'playlist_continuation', 'playlist_large', 'podcast', 'related', 'single',
    ]
    paths = ['daemon/server/src/ytmusic/testdata/' + name + '.json' for name in names]
    paths.append('daemon/server/tests/fixtures/next_radio.json')
    with tempfile.TemporaryDirectory(prefix='anonymous-fixture-policy-') as temporary:
        root = Path(temporary)
        fixture = root / 'fixture'
        for relative in paths:
            source = ROOT / relative
            target = fixture / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            # Each alias is an actual recorded Git rename, not an invented
            # directory-wide exception. Policy generation retains the proof.
            historical = fixture / relative.replace('daemon/server/', 'crates/server/', 1)
            historical.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, historical)
        status, findings = scan(fixture, root / 'anonymous-allowed.json')
        assert status == 0 and not findings, 'Known anonymous response fixture was rejected'

        relative = paths[0]
        document = json.loads((ROOT / relative).read_text())
        def feedback(value):
            result = []
            if isinstance(value, dict):
                token = value.get('feedbackToken')
                if isinstance(token, str) and len(token) >= 20:
                    result.append(token)
                for item in value.values():
                    result.extend(feedback(item))
            elif isinstance(value, list):
                for item in value:
                    result.extend(feedback(item))
            return result
        import collections
        import math
        def entropy(token):
            counts = collections.Counter(token)
            return -sum((n / len(token)) * math.log2(n / len(token)) for n in counts.values())
        known = max(feedback(document), key=entropy)
        assert known, 'Positive fixture no longer contains the reviewed feedback field'
        # Keep the positive fixtures and introduce three independent negatives.
        # The field and path must BOTH match an exact approved old value.
        novel = hashlib.sha256(b'synthetic-new-value-for-policy-regression').hexdigest()
        assert novel != known
        (fixture / relative).write_text(json.dumps({'feedbackToken': novel}))
        (fixture / 'other.json').write_text(json.dumps({'feedbackToken': known}))
        second = fixture / paths[1]
        second.write_text(json.dumps({'session_token': known}))
        status, findings = scan(fixture, root / 'anonymous-rejected.json')
        assert status == 1, 'Fixture exception hides a different credential'
        actual = {item['File'].replace('\\', '/') for item in findings}
        # The decoder can report encoded and decoded forms separately. Every
        # negative case must be detected, with no unrelated positive fixture.
        assert actual == {relative, 'other.json', paths[1]}, actual
        assert all(item['RuleID'] == 'generic-api-key' for item in findings)


if __name__ == '__main__':
    test_policy()
    test_anonymous_fixture_exceptions_are_exact()
