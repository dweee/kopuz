# Release and update automation

`main` (or the configured source branch) accepts development changes. `tested`
advances only after the entire explicit native inventory and flake checks build
and upload, and every path of the built closures passes the cache metadata gate:
Niks3 serves a narinfo for each root with a valid Niks3 signature, every other
path is served by Niks3 with the Niks3 signature or, when Niks3 omitted it, by
cache.nixos.org with the official signature, and narHash, narSize and references
equal the build (the signature binds them). Lookups are parallel and batched;
no NAR bytes are read before promotion, so a missing or corrupt NAR object
behind a valid signed narinfo is not caught here. The daily audit below reads
those bytes, and downstream deployments that substitute the closure are the
end-to-end proof.
Each target closure is policy checked and uploaded as soon as it builds. Valid
locally built or custom-cache outputs from its recursive derivation graph are
also published, including fixed-output/vendor dependencies and completed work
after a later build failure. Official-upstream-signed substitutes are filtered
using local metadata; this is not an independent upstream availability proof. These partial cache entries do not
advance a channel; promotion still waits for the full inventory, native checks,
and the metadata gate.
`stable` is an owner-dispatched selection of an immutable `tested-<commit>` tag;
it repeats builds/checks/cache verification. Flakes continue to lock exact commits.
Failed, skipped or missing platforms never advance a channel. Promotion uses
non-forced atomic pushes; release tags are immutable. No host activation occurs.
`excludedSystems` records intentional exclusions from that guarantee. Private
Darwin outputs use the on-prem native Forgejo runner and its immutable host
admission check before new package/check builds. An explicitly configured ARM
Mac may provide Intel Darwin compatibility only with Nix extra-platforms and
working Rosetta; other platform mismatches are rejected. Missing runner capacity
or an incomplete platform never counts as successful release/cache coverage.

Niks3 garbage-collects closures that were not pushed within its retention
window unless a pin names them. Each build writes a small `release-roots`
manifest per system (a store path whose references are exactly the release
roots), pushes it pinned as `<owner>-<name>.<system>.candidate`, and the
release tag records it under `retention`. Before that, the build re-pins the
advertised `tested`/`stable` releases and the three newest tags per channel
under fixed role names (`.tested`, `.stable`, `.tested-recent-1` ...). Pins
are only created or moved, never deleted; a moved pin returns its previous
closure to the normal push-age window. A pin failure fails the build, so the
channel does not advance. Releases tagged before manifests existed are kept
only by the push-age window until they leave the recovery set.

The daily full run also verifies the advertised tested/stable revisions and the
three newest tags per channel against their original build proofs, without
source builds. It reads and hashes every NAR, so it is the content audit; it
does not gate promotion. Historical helper code is never executed. No release
or cache objects are deleted by this automation. Older tags remain immutable
source selections, but only this bounded recovery set is pinned and actively
rechecked; cache uptime is still monitored separately.

Every six hours, the updater resolves `tracking-inputs.json`, uses Nix to write
the lock, pins Git sources exactly in flake.nix and evaluates. Changed pins go
to one `automation/input-updates` branch and PR per repository, updated in place.
On Forgejo that PR squash-merges itself once the required checks pass
(`"inputAutoMerge": false` in channels.json turns this off).
The manual-version monitor maintains one issue with candidates, failed checks,
and unclassified files. Dynamic/unrecognized sources require manual review.
This is monitoring, not blind rewriting of coordinated dependency hashes.

Required repository configuration:

- Enable Actions and permit the repository workflow token to create branches,
  tags, PRs and monitoring issues. Protect `tested`/`stable` against human or
  unrelated automation writes; allow only the release workflow identity.
- Forgejo requires repository-scoped `FLAKEY_NIKS3_READ_NETRC` and
  `FLAKEY_NIKS3_WRITE_TOKEN`. Niks3 is its substitute and verified release cache.
- GitHub requires no Niks3 static secrets: trusted publishers request a write grant through
  OIDC with audience `https://niks3.monke.fail`. Trusted readers use the separate
  read-only audience `https://niks3.monke.fail/read` and `/oidc` cache object route,
  refreshing the job-local netrc until cleanup. PR events receive no private
  reader. Niks3 upload and signed remote metadata gate releases. No private
  Forgejo source credentials or inputs go to GitHub.
- GitHub release build jobs hold `checks: write` and keep one check run per
  system (`release progress / <system>`) updated with the current target, check
  count or phase, because GitHub serves job logs only after a job ends. Follow
  it with `gh api repos/OWNER/NAME/commits/SHA/check-runs --jq
  '.check_runs[] | select(.name | startswith("release progress")) | [.name, .status, .output.title]'`.
  The token never reaches Nix; a killed job leaves its check run in progress.
- Native flake checks whose outputs are already built inventory roots (for
  example `checks = self.packages // { ... }`) are not built a second time; only
  the remaining checks run.
- Retention pins use the same publisher grant (write scope; creating or moving a
  pin needs no admin rights). The build reads the release ledger read-only: the
  job token on Forgejo, anonymously for public GitHub repositories. Pin names are
  not reserved by default, so any publisher can move them; the Niks3 server can
  reserve each repository's `<owner>-<name>.*` prefix for that repository.
- `inputCheckWorkflows` lists reviewed GitHub native workflows with workflow_dispatch.
  The updater explicitly dispatches them on the update branch head, including
  when using GITHUB_TOKEN. Each workflow must keep cache publication and secrets
  restricted to the trusted source branch. The updater requires Actions write.
  It waits for the dispatched PR checks workflow’s `test` job on the exact head
  and publishes its success with the GitHub Actions token and Statuses write.
- Optional `UPDATE_TOKEN` is a repository-scoped app/PAT. With GITHUB_TOKEN,
  GitHub requires approval before the pull_request workflow runs.
- Each update is a commit of the current target branch plus the new pins, with
  the previous update head as a parent, so the branch only moves forward and is
  never force-pushed. A candidate whose checks are still pending is left to
  finish for up to 12 hours. Older hash-named input-only PRs are closed;
  candidates containing source fixes are preserved for review.
- Optional `CHANNEL_TOKEN` can identify a separate protected-branch publisher.
- Forgejo requires the existing native `nix` and native aarch64 Linux runners. Flakey
  and private inputs never go to GitHub. Already-public GitHub owning repos may
  use their existing native hosted Darwin builders independently.
- Every job reads and publishes through the public HTTPS Niks3 URL. The aarch64
  Linux retention job runs on braco, which executes one job at a time: it queues
  behind other repositories' aarch64 jobs.
- Schedules keep their cadence (release channels nightly, input updates every six
  hours) but start at a per-repository offset derived from a SHA-256 of
  `owner/name`: release channels at a minute of the UTC day (00:00-23:59), input updates at a
  minute in each six-hour slot starting at hour 0-5 UTC. The offset is stable, so
  repositories no longer fire in the same minute.
- On Forgejo, `UPDATE_TOKEN` belongs to the restricted `flakey-updater` account. A
  restricted account has no implicit repository access (the API answers 404), so
  the owner must grant it write access to this repository once, with an admin
  token: `ci/ensure-updater-access.py --repository OWNER/NAME` in dave-fork-ci.
- Forgejo may supply `GH_READ_TOKEN` for authenticated public metadata reads.
  Private input readers belong only on Forgejo; configure them before input jobs.

The helper source lives in dave-fork-ci/ci. `channel-tool-hashes.json` identifies
the installed bytes. Update the controller first, then regenerate/review copies
with `install-channel-automation.py`; do not silently download a moving script
into a credentialed publisher.
