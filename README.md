# GitHub Release -> Gitea download mirror

This directory is a standalone automation candidate. It is intentionally
outside the game and the public product Git. Do not copy it into
`Chronicles of Pripyat 4.26 IX-Ray` or package it with the game.

## Design

The source of truth is `manifest-dev.json` from the persistent GitHub Release
tag `dev-2026.08.26.1`. The permanent Gitea target is the Release tag
`dev-channel` in `hardcoon/chronicles-of-pripyat-ixray-downloads`; it does not
change when the manifest version changes.

The script mirrors only:

- every asset in top-level `fullPackages`, `deltaPackages` and
  `initialPackages`;
- every supported historical delta in `deltaTransitions[*].packages`;
- `ChroniclesLauncher.exe`;
- `manifest-dev.json`, strictly last.

Duplicate package names must have identical size and SHA-256. Source GitHub
metadata, manifest size/SHA, the streamed local file, Gitea attachment size,
and an anonymous full download of every newly uploaded asset are checked.
Package filenames are immutable: a same-name mismatch aborts instead of
deleting data. The mutable launcher and manifest use a staged, anonymous
SHA-verified handover. Gitea permits duplicate attachment names, so a
replacement is renamed to the canonical name while the previous canonical ID
still exists. The previous ID is deleted only after the new ID passes another
anonymous check through its per-attachment UUID URL. Gitea's API normally
returns a name-based `browser_download_url`, which is ambiguous during this
handover; the script requires every API record to have a unique valid UUID and
constructs `/attachments/<uuid>` for identity-bound verification. A missing,
repeated, or changed UUID, or an unavailable anonymous UUID route, fails closed
without deduplication or deletion. The stable
`/releases/download/dev-channel/<canonical-name>` route is checked after the
old ID is gone. There is no interval in which an already-published canonical
name is absent.

The first launcher/manifest upload follows the same protocol: it is uploaded
under a unique `.pending-...` name and anonymously SHA-verified before its
single rename makes the canonical name active. If an upload, rename, or delete
times out after Gitea actually committed it, the script refreshes the Release
and reconciles the result by attachment ID. A rerun also repairs a verified
`.pending-...` upload, duplicate canonical IDs left between rename and delete,
and the `.previous-...` state created by the superseded swap implementation.
Only the exact legacy transaction syntax is recognized; arbitrary
prefix-shaped attachments are not transaction-owned and are never swept. A
recovered pending ID is also left intact if its repeat verification fails. The
script never deletes the sole verified canonical attachment.

Before any write, the source manifest is compared with every canonical target
manifest and every exactly recognized legacy `.previous-...` checkpoint.
Versions must use `YYYY.MM.DD-dev.N`; the global `N`, not the date, is
monotonic. A larger `N` advances the mirror. Equal `N` is idempotent only when
`contentHash` also matches. A lower `N` or equal `N` with different content
fails closed. Cleanup is enabled only after this complete checkpoint set has
passed the progression guard. The workflow fixes all writes to the persistent
source tag `dev-2026.08.26.1`; it has no manual `source_tag` write input.

There is deliberately no sweep that deletes old, unreferenced, or otherwise
"stale" Release assets. This matters because an older delta can still be a
valid transition for an installed game. The only deletions performed by the
script are narrowly transactional: the exact ID/UUID returned for its current
failed temporary upload and the explicit previous canonical IDs captured by a
replacement after the new UUID is verified. It does not delete temporary IDs
merely because their names share `.pending-` or `.previous-` prefixes.
Immutable ZIP packages and unrelated attachments are never deleted. Package
names underneath launcher/manifest mutable namespaces are rejected by schema
validation so package data can never be mistaken for transaction state.

Transfers are sequential and use a single file per Gitea API request. A hosted
GitHub Actions runner processes only one asset at a time. During anonymous
post-upload verification its temporary disk can hold the source file plus one
verification copy of that same asset, never the complete game. The author's PC
neither downloads nor uploads the game:

```text
GitHub Release -> GitHub-hosted runner temporary disk -> Gitea Release
```

The first bootstrap still has to transfer the current approximately 20.8 GB
once between the services. Later runs reuse unchanged package attachments and
transfer only new or replaced assets. Gitea's API does not provide resumable
Release-attachment uploads, so an interrupted individual asset is retried from
the beginning on the next run.

## Authentication and one-time setup

1. Keep the **public** Gitea repository
   `hardcoon/chronicles-of-pripyat-ixray-downloads` with a real `main` commit.
   The script intentionally does not create or delete repositories.
2. Put this directory in a small, separate GitHub automation repository, not
   in the public product repository.
3. In Gitea, create a personal access token under **Settings -> Applications**
   with only `write:repository`. Gitea defines `write` as including read access.
   A PAT scope is an API-unit scope, not a restriction to one repository, so a
   dedicated mirror service account with collaborator access only to the
   download repository is the safest long-term owner if that is practical.
4. Create the protected GitHub Environment `gitea-production`, allow deployment
   only from the `main` branch, and save the token only as that Environment's
   `GITEA_TOKEN` secret. Do not create a repository-level secret with this name;
   revoke any token that was previously stored there. Never put the token on
   disk, in Git, a workflow argument, the launcher, a manifest, a log, or a
   Release asset. GitHub's automatic `${{ github.token }}` is sufficient for
   reading the public source Release; it cannot write to Gitea.
   The read-only `plan` job has no Environment and never receives
   `GITEA_TOKEN`. The separate `write` job runs only for `refs/heads/main`,
   checks out that exact planned commit without persisted credentials, and is
   the only job admitted to `gitea-production`.
5. Leave repository variables `GITEA_MIRROR_WRITE_ENABLED` and
   `GITEA_MIRROR_SCHEDULE_ENABLED` absent or `false` initially.

The workflow intentionally runs on `ubuntu-latest` at GitHub. Gitea Actions
does have a built-in per-job `${{ secrets.GITEA_TOKEN }}` with configurable
`releases: write` permissions, but that token exists only inside a Gitea
Actions job. It cannot be obtained by a GitHub-hosted job. The public
gitea.com service also does not supply a hosted runner for this repository, so
using it would require maintaining a private runner; this rollout therefore
uses the narrowly scoped PAT above.

Gitea's built-in continuous Git mirror is not used. gitea.com currently
advertises repository mirrors as disabled, and Git mirroring would not copy
GitHub Release attachments in any case.

Official references:

- [Gitea API authentication and PAT scopes](https://docs.gitea.com/development/api-usage/)
- [Gitea Actions job-token permissions](https://docs.gitea.com/usage/actions/token-permissions/)
- [Gitea Release attachment limits](https://docs.gitea.com/administration/config-cheat-sheet/#repository---release-repositoryrelease)

## Safe rollout

Run local, read-only checks first:

```powershell
python -m unittest discover -s tests -v
python -m py_compile mirror_release_assets.py
python mirror_release_assets.py --dry-run --probe-largest-full `
  --plan-out $env:TEMP\cop-gitea-large-probe-plan.json
```

Then use **Actions -> Mirror release assets to Gitea -> Run workflow** in this
exact order:

1. Keep both gates disabled and choose `operation=plan`. This performs API
   reads only and saves the exact asset list and byte total as an artifact.
   Review the target tag (`dev-channel`), version, content hash, approximately
   20.8 GB total, and `manifestIsLast=true`.
2. Set only `GITEA_MIRROR_WRITE_ENABLED=true`.
3. Choose `operation=probe-largest-full` and
   `verify_existing_sha=true`. This uploads and anonymously hashes just the
   largest full package, but does **not** upload the launcher or manifest and
   cannot activate the mirror. The selection is derived from the current
   manifest. For manifest `2026.09.05-dev.29`, the expected probe is
   `cop-2026.08.26-dev.1-full-03.zip`, 1,960,473,562 bytes, SHA-256
   `c7be9dbbd3235bc1d59cff5a84c1a642db4bc1230e02f16fa83ffd4875f40d28`.
4. Inspect the probe receipt and anonymously download/check the resulting
   canonical attachment. A successful probe remains in `dev-channel` and is
   reused by the bootstrap, so those roughly 1.96 GB are not uploaded twice.
   If the server returns HTTP 413 or the job times out, stop: the manifest is
   unchanged and no launcher can select an incomplete Gitea mirror.
5. Choose `operation=mirror` and `verify_existing_sha=true`. Assets transfer
   one by one; all packages and the launcher are checked before
   `manifest-dev.json` is replaced last.
6. Check anonymous manifest, launcher, package downloads, and HTTP Range
   resume from Gitea, then perform the launcher server-selection smoke test.
7. Only after that succeeds set `GITEA_MIRROR_SCHEDULE_ENABLED=true`. The
   hourly job is now allowed to run full incremental synchronization.

The workflow has one concurrency group and never cancels a run in progress,
so two manifest switches cannot overlap. Scheduled writes require **both**
variables. Manual `plan` remains available with neither variable. Manual
`probe-largest-full` and `mirror` fail closed unless the write gate is true.

There is deliberately no rollback control in the workflow. For a separately
reviewed emergency recovery, direct script use requires both
`--allow-rollback` and the exact process environment guard
`GITEA_MIRROR_ROLLBACK_ENABLED=true`; either one alone fails closed. This
break-glass path also covers a non-default source tag and is not part of normal
scheduled or manual Actions operation.

The documented Gitea default for one Release attachment is 2048 MB and the
maximum files per upload is five. The script uploads one file per API request,
so the count limit is not relevant; the one-asset probe measures the real
gitea.com file/proxy/time limit before committing to the 20.8 GB bootstrap.
Documentation is not proof of the hosted instance's effective limit.

## Existing-asset verification policy

Every new or replaced attachment is downloaded anonymously from Gitea and
hashed through its constructed UUID route. Mutable `ChroniclesLauncher.exe`
and `manifest-dev.json` are re-hashed on every run. Published canonical and
exact legacy-checkpoint manifests are themselves UUID-downloaded, parsed, and
combined into a strict immutable trust map. An existing package can skip a
full audit only when its exact `(name, size, sha256)` tuple occurs in that map;
conflicting historical tuples for one name fail closed. An orphan asset, or a
same-name/size asset whose expected SHA is not certified by the map, is always
anonymously hashed and a mismatch aborts without deletion. Use
`--verify-existing-sha` to re-hash even certified packages.

Every successful hash or trust-map reuse creates an in-memory certificate for
one exact target `(id, uuid, name, size, sha256)`. Immediately before the
manifest switch, a fresh Release snapshot must still contain exactly those
certified IDs and UUIDs for every package and the launcher. A size-only asset
listing can never satisfy this gate. Bootstrap naturally hashes every
pre-existing package because no published manifest can yet supply trust. The
launcher independently validates every downloaded package SHA-256 before
installation.
