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
         '--report-format', 'json', '--report-path', str(report), str(directory)],
        capture_output=True, text=True, timeout=30)
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


if __name__ == '__main__':
    test_policy()
