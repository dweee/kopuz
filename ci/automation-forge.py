#!/usr/bin/env python3
"""Publish one update PR or maintain one monitoring issue on the owning forge."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

sys.dont_write_bytecode = True  # see release-channel.py
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


# Idempotent reads are retried after transport failures; writes are never retried.
API_RETRY_DELAYS = (5, 20)
API_RETRY_STATUS = {502, 503, 504}


def transient_api_failure(error):
    if isinstance(error, HTTPError):
        return error.code in API_RETRY_STATUS
    return isinstance(error, (URLError, socket.timeout, TimeoutError, ConnectionError))


def api(rules, method, endpoint, data=None):
    delays = iter(API_RETRY_DELAYS if method == 'GET' else ())
    while True:
        try:
            return api_once(rules, method, endpoint, data)
        except (HTTPError, URLError, OSError) as error:
            delay = next(delays, None)
            if delay is None or not transient_api_failure(error):
                raise
            if isinstance(error, HTTPError):
                error.close()
            print('Retrying ' + method + ' after a transient API failure in ' + str(delay) + 's', file=sys.stderr, flush=True)
            time.sleep(delay)


def api_once(rules, method, endpoint, data=None):
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


PR_CHECKS = 'pr-checks.yml'
INPUT_MARKER = '<!-- tracked-input-update -->'
INPUT_FILES = ('flake.nix', 'flake.lock', 'nix/forks.json')
# One long-lived branch and PR per repository, updated in place. Older releases
# named a new branch after every pin set; those PRs are still recognised so the
# first run on this version can close them.
INPUT_BRANCH = 'automation/input-updates'
LEGACY_INPUT_PREFIX = 'automation/input-updates-'
INPUT_COMMIT = ['-c', 'user.name=Input updater', '-c', 'user.email=input-updater@monke.fail']
# A push restarts the PR's checks. Leave a candidate whose checks are still
# running, so a slow check queue cannot cancel every candidate in turn, unless
# its checks have been pending for longer than this.
PENDING_GRACE_SECONDS = 12 * 3600


def input_pr(rules, pr):
    ref = pr.get('head', {}).get('ref', '')
    return (INPUT_MARKER in (pr.get('body') or '')
            and pr.get('base', {}).get('ref') == rules['branch']
            and (ref == INPUT_BRANCH or ref.startswith(LEGACY_INPUT_PREFIX))
            and pr.get('head', {}).get('repo', {}).get('full_name', '').lower() == rules['repository'].lower())


def dispatch_input_checks(rules, prefix, pr):
    if rules['forge'] != 'github':
        return
    branch, sha = pr['head']['ref'], pr['head']['sha']
    configured = rules.get('inputCheckWorkflows', [])
    # A PR opened with the workflow token starts no pull_request run, so the
    # required `test` check is reported by dispatching the PR checks workflow too.
    for workflow in configured + ([] if PR_CHECKS in configured else [PR_CHECKS]):
        if not re.fullmatch(r'[A-Za-z0-9_-]+[.]ya?ml', workflow):
            raise ValueError('Invalid input check workflow')
        endpoint = prefix + '/actions/workflows/' + workflow
        try:
            runs = api(rules, 'GET', endpoint + '/runs?head_sha=' + sha + '&per_page=1' + ('&event=workflow_dispatch' if workflow == PR_CHECKS else ''))
            if not runs.get('workflow_runs'):
                phase('dispatch-input-checks')
                api(rules, 'POST', endpoint + '/dispatches', {'ref': branch})
        except HTTPError as error:
            error.close()
            # The implicit PR checks workflow may not be dispatchable on older installs.
            if workflow in configured or error.code not in (404, 422):
                raise
            print('PR checks workflow cannot be dispatched; update the installed automation')


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


def remote_input_head(rules, env):
    """The update branch's current revision, fetched for use as a parent, or None."""
    phase('read-input-branch')
    listed = channel.run('git', '-c', 'credential.helper=', 'ls-remote', rules['remote'],
                         'refs/heads/' + INPUT_BRANCH, env=env)
    if not listed:
        return None
    phase('fetch-input-branch')
    channel.run('git', '-c', 'credential.helper=', 'fetch', '-q', '--no-tags', rules['remote'],
                'refs/heads/' + INPUT_BRANCH, env=env)
    head = channel.run('git', 'rev-parse', 'FETCH_HEAD^{commit}')
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('Invalid update branch revision')
    return head


def proposes_staged_pins(head):
    return not channel.run('git', 'diff', '--cached', '--name-only', head, '--', *INPUT_FILES)


def checks_still_running(rules, prefix, head):
    if rules['forge'] != 'forgejo':
        return False
    phase('read-input-checks')
    state = (api(rules, 'GET', prefix + '/commits/' + head + '/status') or {}).get('state')
    age = time.time() - int(channel.run('git', 'show', '-s', '--format=%ct', head))
    return state == 'pending' and age < PENDING_GRACE_SECONDS


def schedule_input_merge(rules, prefix, pr):
    # Forgejo only; the GitHub REST API has no auto-merge. Pin-only changes still
    # have to pass the required PR checks, and channel promotion still gates hosts.
    if rules['forge'] != 'forgejo' or rules.get('inputAutoMerge') is False:
        return
    phase('schedule-input-merge')
    try:
        api(rules, 'POST', prefix + '/pulls/' + str(pr['number']) + '/merge',
            {'Do': 'squash', 'merge_when_checks_succeed': True, 'delete_branch_after_merge': True})
    except HTTPError as error:
        error.close()
        if error.code == 409:
            return  # already scheduled
        if error.code == 405:
            print('Automatic merge is not allowed for update PR ' + str(pr['number']) + '; it awaits review')
            return
        raise
    print('Update PR ' + str(pr['number']) + ' merges when its required checks pass')


def inputs(rules):
    phase('inspect-input-diff')
    changed = channel.run('git', 'diff', '--name-only', '--', *INPUT_FILES)
    if not changed:
        print('Tracked inputs are unchanged')
        return
    names = changed.splitlines()
    phase('stage-input-pins')
    channel.run('git', 'add', '--', *names)
    tree = channel.run('git', 'write-tree')
    base = channel.run('git', 'rev-parse', 'HEAD^{commit}')
    prefix = '/repos/' + rules['repository']
    phase('find-existing-input-pr')
    prs = api(rules, 'GET', prefix + '/pulls?state=open&limit=100&per_page=100')
    current = next((p for p in prs if p.get('head', {}).get('ref') == INPUT_BRANCH and input_pr(rules, p)), None)
    with channel.tempfile.TemporaryDirectory(prefix='input-push-') as directory:
        with channel.build_environment(dict(os.environ, CHANNEL_TOKEN=os.environ['AUTOMATION_TOKEN'])):
            env = channel.git_env(directory)
            head = remote_input_head(rules, env)
            if head and proposes_staged_pins(head):
                print('The update PR already proposes these pins')
            elif current and head and checks_still_running(rules, prefix, head):
                print('Leaving update PR ' + str(current['number']) + ' to finish its checks')
            else:
                # The proposal is always the current base plus the new pins. The
                # previous branch head is kept as a parent, so the branch only
                # moves forward and never needs a force push; the PR diff against
                # the base stays the pin files alone.
                parents = ['-p', base]
                if head and channel.run('git', 'merge-base', head, base) != head:
                    parents = ['-p', head] + parents
                phase('commit-input-pins')
                head = channel.run('git', *INPUT_COMMIT, 'commit-tree', tree, *parents,
                                   '-m', 'Update tracked flake inputs to exact revisions')
                phase('push-input-branch')
                channel.run('git', '-c', 'credential.helper=', 'push', rules['remote'],
                            head + ':refs/heads/' + INPUT_BRANCH, env=env)
                print('Updated ' + INPUT_BRANCH + ' to ' + head)
    if not current:
        body = attribution(rules) + ('Track the configured channels/branches while retaining exact source and lock pins. '
            'Nix resolved the lockfile and `nix flake check --no-build` passed. '
            'This PR is updated in place when the pins move again. '
            'Required native release builds, cache uploads and independent cache reads still gate channel promotion. '
            'No host activation is authorized.\n\n' + INPUT_MARKER)
        phase('create-input-pr')
        current = api(rules, 'POST', prefix + '/pulls', {'title': 'Update tracked flake inputs',
                                                       'head': INPUT_BRANCH, 'base': rules['branch'], 'body': body})
        print(current.get('html_url', 'Created input update PR'))
    # The listed PR head predates a push made by this run.
    dispatch_input_checks(rules, prefix, {'head': {'ref': INPUT_BRANCH, 'sha': head}})
    schedule_input_merge(rules, prefix, current)
    consolidate_input_prs(rules, prefix, prs, current)


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
