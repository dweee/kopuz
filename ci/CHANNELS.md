# Release and update automation

`main` (or the configured source branch) accepts development changes. `tested`
advances only after the entire explicit native inventory and flake checks build,
upload, and pass independent remote NAR content and signature verification.
`stable` is an owner-dispatched selection of an immutable `tested-<commit>` tag;
it repeats builds/checks/cache verification. Flakes continue to lock exact commits.
Failed, skipped or missing platforms never advance a channel. Promotion uses
non-forced atomic pushes; release tags are immutable. No host activation occurs.
`excludedSystems` records intentional exclusions from that guarantee. Private
repositories exclude Darwin; their Darwin outputs remain available for manual
use without claiming a successful Darwin build/cache gate. Darwin-only private
tools have monitoring/input updates but no automatic tested/stable channel.

The daily full run also verifies the advertised tested/stable revisions and the
three newest tags per channel against their original build proofs, without
source builds. NAR reads refresh Attic's last-access retention window. Historical
helper code is never executed. No release/cache objects are deleted by this
automation. Older tags remain immutable source selections, but only this bounded
recovery set is actively kept warm; cache uptime is still monitored separately.

Every six hours, the updater resolves `tracking-inputs.json`, uses Nix to write
the lock, pins Git sources exactly in flake.nix, evaluates, and opens a review PR.
The manual-version monitor maintains one issue with candidates, failed checks,
and unclassified files. Dynamic/unrecognized sources require manual review.
This is monitoring, not blind rewriting of coordinated dependency hashes.

Required repository configuration:

- Enable Actions and permit the repository workflow token to create branches,
  tags, PRs and monitoring issues. Protect `tested`/`stable` against human or
  unrelated automation writes; allow only the release workflow identity.
- Supply a repository-scoped `ATTIC_TOKEN` (or `FLAKEY_ATTIC_TOKEN`) with pull/push
  access to the existing `flakey` cache. No private Forgejo inputs go to GitHub.
- Optional `UPDATE_TOKEN` is a repository-scoped app/PAT. On GitHub, use it when
  generated PRs must trigger further workflows; default GITHUB_TOKEN PRs do not.
- Optional `CHANNEL_TOKEN` can identify a separate protected-branch publisher.
- Forgejo requires the existing native `nix` and `braco` Linux runners. Flakey
  and private inputs never go to GitHub. Already-public GitHub owning repos may
  use their existing native hosted Darwin builders independently.
- Forgejo may supply `GITHUB_READ_TOKEN` for authenticated public metadata reads.
  Private input readers belong only on Forgejo; configure them before input jobs.

The helper source lives in dave-fork-ci/ci. `channel-tool-hashes.json` identifies
the installed bytes. Update the controller first, then regenerate/review copies
with `install-channel-automation.py`; do not silently download a moving script
into a credentialed publisher.
