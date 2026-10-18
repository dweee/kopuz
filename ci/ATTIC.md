# Private Flakey cache publication

The catalog and five application forks publish free, disc-independent package
closures to **https://attic.monke.fail/flakey**, a private Attic cache. Its signing
key is `flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8=`.
There is one destination. Publisher helpers reject any other endpoint or cache.

## Repository setup

An Attic administrator issues a dedicated token with only pull and push on
`flakey`, valid for at most 90 days:

```sh
atticadm make-token --sub github-packages --validity 90d --pull flakey --push flakey
```

Save the token privately to a file; do not paste it into commands, logs or Git.
On a machine with authenticated GitHub CLI, set the existing secret and enable
variables. This reads the token directly from the file without printing it:

```sh
token_file=/absolute/path/to/github-flakey-token
for repo in dave-packages kopuz paneru tabrix schildi-revenge rekordbox-mcp; do
  gh secret set ATTIC_TOKEN --repo "dweee/$repo" < "$token_file"
  gh variable set ATTIC_ENDPOINT --repo "dweee/$repo" --body https://attic.monke.fail
  gh variable set ATTIC_CACHE --repo "dweee/$repo" --body flakey
  gh variable set ATTIC_SUBSTITUTER --repo "dweee/$repo" --body https://attic.monke.fail/flakey
  gh variable set ATTIC_PUBLIC_KEY --repo "dweee/$repo" --body 'flakey:mDx4DiNpH5w1Pl8OAKFFWq1ZsypA9lbaFKNiRWhqYE8='
  gh variable set ATTIC_PUSH_ENABLED --repo "dweee/$repo" --body true
  if test "$repo" = dave-packages; then
    gh variable set DAVE_PACKAGES_CI_ENABLED --repo "dweee/$repo" --body true
  else
    gh variable set DAVE_FORK_CI_ENABLED --repo "dweee/$repo" --body true
    gh variable set GUARDED_UPSTREAM_SYNC_ENABLED --repo "dweee/$repo" --body false
  fi
done
```

Endpoint/cache/key variables are also set for compatibility with existing repo
administration. The native publisher and read helper pin the values above.
Rotate the secret before its token expires. No host credential is reused.

## Trusted reads and writes

Only a push or manual dispatch on the repository's default branch receives the
secret. The read helper creates `$RUNNER_TEMP/flakey-attic.netrc` with mode 0600
and configures Nix's `netrc-file`; the token does not enter Nix expressions,
derivations, the store or artifacts. The netrc authenticates to `attic.monke.fail`.
Pull request and other-branch builds read the official upstream cache and receive
no Attic token. They cannot publish. CI enable switches remain respected.

Native builders use the pinned Nix quick installer with Nix 2.34.7 on
`ubuntu-24.04`, `ubuntu-24.04-arm`, and `macos-15`. Linux kernel builders reclaim
unused .NET, Android and GHC SDK space and allow up to six hours per package.
The catalog builds one package per matrix job, rather than a complete host.

Only successful default-branch push/dispatch runs enter the separate publisher.
It installs the pinned Attic client from the official cache with local builds
disabled, imports selected NAR data without executing it, verifies the runtime
closure, restores upstream signatures, then pushes roots and runtime closures.
Selected output roots are pushed first with `--no-closure` and
`--ignore-upstream-cache-filter`, so even roots already signed upstream get
narinfo in `flakey`. A second normal closure push retains upstream filtering
for dependencies. Either push failing fails publication.
The token is stored in a temporary mode-0600 Attic configuration, removed from
the client's environment, never passed in command arguments, and removed after
success or failure. Failed publication fails the job.

The four shared upstream synchronization jobs are paused behind
`GUARDED_UPSTREAM_SYNC_ENABLED` (unset or false): their pinned shared
controller builds with public logs and exports public closure artifacts without
this migration's recursive policy. They receive no Attic secret and have cache
publication disabled. Resume them only after the shared controller applies the
same pre-build and export checks. Native PR/push/dispatch builds remain enabled;
a merge to the default branch triggers the guarded native publisher.

## Public build and backup policy

These repositories and their closure artifacts/releases are public. Before any
package build with logs, `ci/public-closure.py` captures and inspects the entire
recursive derivation graph. It rejects the disc input, VeraCrypt, proprietary
NVIDIA 580, ffmpeg-full and subnetter, including transitive references. Failure
prints a generic diagnostic without the rejected path or evaluator output.
Nixpkgs is imported with `allowUnfree = false` as an independent evaluation gate.

Only these Wii attributes are approved, and each still requires the recursive
derivation check: `wiicompiled-native-prebuilt`, `wiicompiled-translator`,
`wiicompiled-setup`, and `wiicompiled-setup-unwrapped`. Final/translated/disc
attributes are rejected before evaluation. Disc-dependent and unfree outputs
remain on premises and may be stored only in the private cache.

Immediately before any NAR archive is created, the export helper checks the
selected outputs' complete runtime closure again. The publisher checks imported
runtime closures before supplying the write credential. No job exports the
whole runner store. Selected free closures are retained as immutable Actions
artifacts for one day; the existing `Preserve package backups` workflow may
copy those archives to public prereleases. These are public redistribution,
which is why the closure policy runs before the archive exists.

Transfers default to a maximum of 4 GiB uncompressed; `ATTIC_MAX_CLOSURE_MIB`
accepts 1–4096 MiB. An oversize closure fails rather than silently dropping data.
Build summaries show build and upload duration. Cache success still requires
checking the consumer's exact output store path and authenticated narinfo URL.

## Credential-free checks

```sh
python3 ci/test-push-attic.py
python3 ci/test-transfer-attic.py
python3 ci/test-public-closure.py
python3 ci/test-configure-attic-read.py
```

To recover a permitted archive, download its `packages-RUN_ID` release assets,
join any numbered ZIP parts, verify the supplied checksums, and import its NAR
with `gzip -dc closure.nar.gz | nix-store --import`. Use `outputs.txt` as the
publisher manifest after repairing cache access; reapply the runtime guard.
