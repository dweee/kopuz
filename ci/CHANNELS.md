# Release and update automation

`main` (or the configured source branch) accepts development changes. `tested`
advances only after the entire explicit native inventory and flake checks build,
upload, and pass independent remote NAR content and signature verification.
Each target closure is policy checked and uploaded as soon as it builds. Valid
locally built or custom-cache outputs from its recursive derivation graph are
also published, including fixed-output/vendor dependencies and completed work
after a later build failure. Official-upstream-signed substitutes are filtered
using local metadata; this is not an independent upstream availability proof. These partial cache entries do not
advance a channel; promotion still waits for the full inventory, native checks,
and independent verification.
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

The daily full run also verifies the advertised tested/stable revisions and the
three newest tags per channel against their original build proofs, without
source builds. These reads prove availability and integrity; they do not replace
the cache server's retention policy. Historical helper code is never executed.
No release/cache objects are deleted by this automation. Older tags remain
immutable source selections, but only this bounded recovery set is actively
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
  `FLAKEY_NIKS3_WRITE_TOKEN`. Niks3 is its substitute and verified release cache;
  existing Attic secrets and historical objects remain.
- GitHub requires no Niks3 static secrets: trusted publishers request a write grant through
  OIDC with audience `https://niks3.monke.fail`. Trusted readers use the separate
  read-only audience `https://niks3.monke.fail/read` and `/oidc` cache object route,
  refreshing the job-local netrc until cleanup. PR events receive no private
  reader. Niks3 upload and signed remote verification gate releases. No private
  Forgejo source credentials or inputs go to GitHub.
- `inputCheckWorkflows` lists reviewed GitHub native workflows with workflow_dispatch.
  The updater explicitly dispatches them on the update branch head, including
  when using GITHUB_TOKEN. Each workflow must keep cache publication and secrets
  restricted to the trusted source branch. The updater requires Actions write.
- Optional `UPDATE_TOKEN` is a repository-scoped app/PAT; default GITHUB_TOKEN
  PRs do not emit further pull_request workflow events.
- Each update is a commit of the current target branch plus the new pins, with
  the previous update head as a parent, so the branch only moves forward and is
  never force-pushed. A candidate whose checks are still pending is left to
  finish for up to 12 hours. Older hash-named input-only PRs are closed;
  candidates containing source fixes are preserved for review.
- Optional `CHANNEL_TOKEN` can identify a separate protected-branch publisher.
- Forgejo requires the existing native `nix` and native aarch64 Linux runners. Flakey
  and private inputs never go to GitHub. Already-public GitHub owning repos may
  use their existing native hosted Darwin builders independently.
- Forgejo jobs on the `nix` runner (x86_64 Linux build and the x86_64 Linux and
  Darwin retention jobs) set `ATTIC_SERVER` to the Attic host's runner-network
  address, so cache reads skip the public reverse proxy. The helpers accept only
  that address, the tailnet address of the same listener, or the public URL, send
  the token to one host only, and keep proofs independent of the transport. The
  braco aarch64 build and retention jobs, Darwin builds and all uploads use the
  public HTTPS URL. The aarch64 Linux retention job runs on braco, which executes
  one job at a time: it queues behind other repositories' aarch64 jobs.
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
