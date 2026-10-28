#!/usr/bin/env python3
"""Publish one update PR or maintain one monitoring issue on the owning forge."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('channel', ROOT / 'ci/release-channel.py')
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)
ACTIVE_PHASE = 'startup'


def phase(label):
    global ACTIVE_PHASE
    if not re.fullmatch(r'[a-z-]+', label):
        raise ValueError('Invalid automation phase')
    ACTIVE_PHASE = label
    print('Repository automation phase: ' + label, flush=True)


def failure_detail(error):
    if isinstance(error, HTTPError):
        error.close()
        kind = ('authorization' if error.code in {401, 403} else
                'missing-input-or-output' if error.code == 404 else
                'rate-limit' if error.code == 429 else
                'transport' if 500 <= error.code <= 599 else 'http-failure')
        detail = kind + ' (HTTP ' + str(error.code) + ')'
        if error.code == 404 and ACTIVE_PHASE.startswith(('find-', 'read-', 'create-', 'update-')):
            # Forgejo answers 404 to a restricted account with no collaborator row.
            detail += (' - if the repository exists, the UPDATE_TOKEN account has no access to it; '
                       'the owner can grant it with dave-fork-ci ci/ensure-updater-access.py')
        return detail
    if isinstance(error, URLError):
        return 'transport'
    if isinstance(error, channel.CommandFailure):
        return str(error)
    kind = channel.failure_category(str(error))
    return 'validation-failed' if kind == 'command-failed' else kind


def api(rules, method, endpoint, data=None):
    origin = 'https://api.github.com' if rules['forge'] == 'github' else 'https://git.monke.fail/api/v1'
    token = os.environ.get('AUTOMATION_TOKEN', '')
    if not token:
        raise ValueError('Missing repository automation token')
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('API redirect refused')
    request = Request(origin + endpoint, method=method,
                      data=None if data is None else json.dumps(data).encode(),
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                               'Accept': 'application/json', 'User-Agent': 'release-automation'})
    with build_opener(NoRedirect()).open(request, timeout=60) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


def attribution(rules):
    if rules['forge'] != 'forgejo':
        return ''
    phase('read-poster-identity')
    account = api(rules, 'GET', '/user')['login']
    return ('**Posted by:** `Forgejo Actions` · **Content:** `none (no model used)` · '
            '**Model:** `none (no model used)` · **Account:** `' + account +
            '` · **Evidence:** `none (no model used)` · **Role:** `report`\n\n')


def report(rules):
    phase('read-monitor-report')
    value = json.loads((Path(os.environ['RUNNER_TEMP']) / 'version-monitor.json').read_text())
    marker = '<!-- release-version-monitor -->'
    body = attribution(rules) + 'Scheduled manual source/version monitoring. Candidates require review; '
    body += 'checks with errors and unclassified files are not considered current.\n\n'
    body += '```json\n' + json.dumps(value, indent=2) + '\n```\n\n' + marker
    prefix = '/repos/' + rules['repository']
    phase('find-monitor-issue')
    issues = api(rules, 'GET', prefix + '/issues?state=open&limit=100&per_page=100')
    existing = next((i for i in issues if marker in (i.get('body') or '') and not i.get('pull_request')), None)
    if existing:
        phase('update-monitor-issue')
        api(rules, 'PATCH', prefix + '/issues/' + str(existing['number']), {'body': body})
    else:
        phase('create-monitor-issue')
        api(rules, 'POST', prefix + '/issues', {'title': 'Manual package and file version monitoring', 'body': body})
    print('Updated the repository version-monitoring issue')


def branch_exists(rules, prefix, branch):
    # The branch name is the staged tree hash, so an existing branch already holds exactly these pins.
    try:
        api(rules, 'GET', prefix + '/branches/' + quote(branch, safe='/'))
    except HTTPError as error:
        error.close()
        if error.code == 404:
            return False
        raise
    return True


INPUT_MARKER = '<!-- tracked-input-update -->'
INPUT_FILES = {'flake.nix', 'flake.lock', 'nix/forks.json'}


def input_pr(rules, pr):
    return (INPUT_MARKER in (pr.get('body') or '')
            and pr.get('base', {}).get('ref') == rules['branch']
            and pr.get('head', {}).get('ref', '').startswith('automation/input-updates-')
            and pr.get('head', {}).get('repo', {}).get('full_name', '').lower() == rules['repository'].lower())


def dispatch_input_checks(rules, prefix, pr):
    if rules['forge'] != 'github':
        return
    branch, sha = pr['head']['ref'], pr['head']['sha']
    for workflow in rules.get('inputCheckWorkflows', []):
        if not re.fullmatch(r'[A-Za-z0-9_-]+[.]ya?ml', workflow):
            raise ValueError('Invalid input check workflow')
        endpoint = prefix + '/actions/workflows/' + workflow
        runs = api(rules, 'GET', endpoint + '/runs?head_sha=' + sha + '&per_page=1')
        if not runs.get('workflow_runs'):
            phase('dispatch-input-checks')
            api(rules, 'POST', endpoint + '/dispatches', {'ref': branch})


def consolidate_input_prs(rules, prefix, prs, current):
    for pr in prs:
        if pr['number'] == current['number'] or not input_pr(rules, pr):
            continue
        files = api(rules, 'GET', prefix + '/pulls/' + str(pr['number']) + '/files?limit=100&per_page=100')
        # Preserve candidates with manual source fixes or an incomplete file list.
        if not files or len(files) >= 100 or any(f['filename'] not in INPUT_FILES for f in files):
            print('Preserving update PR with additional changes: ' + str(pr['number']))
            continue
        phase('close-superseded-input-pr')
        api(rules, 'PATCH', prefix + '/pulls/' + str(pr['number']), {'state': 'closed'})


def inputs(rules):
    phase('inspect-input-diff')
    changed = channel.run('git', 'diff', '--name-only', '--', 'flake.nix', 'flake.lock', 'nix/forks.json')
    if not changed:
        print('Tracked inputs are unchanged')
        return
    names = changed.splitlines()
    phase('stage-input-pins')
    channel.run('git', 'add', '--', *names)
    tree = channel.run('git', 'write-tree')
    branch = 'automation/input-updates-' + tree[:16]
    prefix = '/repos/' + rules['repository']
    phase('find-existing-input-pr')
    prs = api(rules, 'GET', prefix + '/pulls?state=open&limit=100&per_page=100')
    current = next((p for p in prs if p.get('head', {}).get('ref') == branch and input_pr(rules, p)), None)
    if current:
        dispatch_input_checks(rules, prefix, current)
        consolidate_input_prs(rules, prefix, prs, current)
        print('An update PR already exists for this input set')
        return
    if branch_exists(rules, prefix, branch):
        print('Reusing the already published branch for this input set')
    else:
        phase('commit-input-pins')
        channel.run('git', '-c', 'user.name=Input updater', '-c', 'user.email=input-updater@monke.fail',
                    'commit', '-m', 'Update tracked flake inputs to exact revisions')
        with channel.tempfile.TemporaryDirectory(prefix='input-push-') as directory:
            with channel.build_environment(dict(os.environ, CHANNEL_TOKEN=os.environ['AUTOMATION_TOKEN'])):
                env = channel.git_env(directory)
                phase('push-input-branch')
                channel.run('git', '-c', 'credential.helper=', 'push', rules['remote'], 'HEAD:refs/heads/' + branch, env=env)
    body = attribution(rules) + ('Track the configured channels/branches while retaining exact source and lock pins. '
        'Nix resolved the lockfile and `nix flake check --no-build` passed. '
        'Required native release builds, cache uploads and independent cache reads still gate channel promotion. '
        'No host activation is authorized.\n\n<!-- tracked-input-update -->')
    phase('create-input-pr')
    pr = api(rules, 'POST', prefix + '/pulls', {'title': 'Update tracked flake inputs',
                                              'head': branch, 'base': rules['branch'], 'body': body})
    dispatch_input_checks(rules, prefix, pr)
    consolidate_input_prs(rules, prefix, prs, pr)
    print(pr.get('html_url', 'Created input update PR'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['report', 'inputs'])
    args = parser.parse_args()
    try:
        rules = json.loads((ROOT / 'ci/channels.json').read_text())
        (report if args.action == 'report' else inputs)(rules)
    except Exception as error:
        print('Repository automation failed during ' + ACTIVE_PHASE + ': ' + failure_detail(error) +
              '; publication did not complete.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
