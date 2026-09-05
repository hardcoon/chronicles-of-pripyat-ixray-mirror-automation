import hashlib
import http.client
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mirror_release_assets as mirror
from mirror_release_assets import (
    AssetSpec,
    GiteaReleaseClient,
    ManifestIdentity,
    MirrorError,
    SourceAsset,
    TargetAsset,
    collect_manifest_assets,
    download_file,
    effective_existing_sha_verification,
    largest_full_package,
    manifest_identity,
    ordered_specs,
    parse_args,
    published_manifest_candidates,
    replace_mutable_attachment,
    rollback_override_enabled,
    sync_asset,
    validate_asset_name,
    validate_manifest_progression,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def package(name: str, size: int, digest: str):
    return {"assetName": name, "size": size, "sha256": digest, "files": []}


def target(asset_id: int, name: str, size: int = 3) -> TargetAsset:
    return TargetAsset(
        id=asset_id,
        name=name,
        size=size,
        download_url=f"https://example.invalid/attachments/{asset_id}",
    )


class FakeResponse:
    def __init__(self, body: bytes, status: int, headers=None):
        self._stream = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeGiteaClient:
    def __init__(
        self,
        assets=(),
        *,
        events=None,
        upload_failure=None,
        rename_failure=None,
        delete_failure=None,
    ):
        self.assets = {asset.id: asset for asset in assets}
        self.events = events if events is not None else []
        self.next_id = max(self.assets, default=0) + 1
        self.upload_failure = upload_failure
        self.rename_failure = rename_failure
        self.delete_failure = delete_failure

    def grouped(self):
        grouped = {}
        for asset in sorted(self.assets.values(), key=lambda item: item.id):
            grouped.setdefault(asset.name, []).append(asset)
        return grouped

    def refresh_assets(self, tag):
        self.events.append(("refresh", tag))
        return {"id": 99}, self.grouped()

    def upload(self, release_id, path, target_name):
        asset = target(self.next_id, target_name, path.stat().st_size)
        self.next_id += 1
        self.events.append(("upload", asset.id, target_name))
        if self.upload_failure == "before":
            self.upload_failure = None
            raise TimeoutError("upload timed out before commit")
        self.assets[asset.id] = asset
        if self.upload_failure == "after":
            self.upload_failure = None
            raise TimeoutError("upload timed out after commit")
        return asset

    def rename(self, release_id, asset_id, name):
        self.events.append(("rename", asset_id, name))
        if self.rename_failure == "before":
            self.rename_failure = None
            raise TimeoutError("rename timed out before commit")
        current = self.assets[asset_id]
        renamed = TargetAsset(current.id, name, current.size, current.download_url)
        self.assets[asset_id] = renamed
        if self.rename_failure == "after":
            self.rename_failure = None
            raise TimeoutError("rename timed out after commit")
        return renamed

    def delete(self, release_id, asset_id):
        self.events.append(("delete", asset_id))
        if self.delete_failure == "before":
            self.delete_failure = None
            raise TimeoutError("delete timed out before commit")
        del self.assets[asset_id]
        if self.delete_failure == "after":
            self.delete_failure = None
            raise TimeoutError("delete timed out after commit")

    def canonical_download_url(self, tag, name):
        return f"https://example.invalid/releases/download/{tag}/{name}"


class ManifestAssetsTests(unittest.TestCase):
    def test_collects_current_and_chain_packages(self):
        manifest = {
            "fullPackages": [package("full.zip", 10, SHA_A)],
            "deltaPackages": [package("direct-delta.zip", 2, SHA_B)],
            "initialPackages": package("initial.zip", 1, SHA_C),
            "deltaTransitions": [
                {
                    "fromVersion": "v1",
                    "toVersion": "v2",
                    "packages": [package("old-delta.zip", 3, SHA_A)],
                }
            ],
        }
        assets = collect_manifest_assets(manifest)
        self.assertEqual(
            set(assets), {"full.zip", "direct-delta.zip", "initial.zip", "old-delta.zip"}
        )

    def test_exact_duplicate_is_allowed(self):
        same = package("same.zip", 10, SHA_A)
        manifest = {
            "deltaPackages": [same],
            "deltaTransitions": [{"packages": [dict(same)]}],
        }
        assets = collect_manifest_assets(manifest)
        self.assertEqual(list(assets), ["same.zip"])

    def test_conflicting_duplicate_fails_closed(self):
        manifest = {
            "deltaPackages": [package("same.zip", 10, SHA_A)],
            "deltaTransitions": [
                {"packages": [package("same.zip", 10, SHA_B)]}
            ],
        }
        with self.assertRaisesRegex(MirrorError, "conflicting"):
            collect_manifest_assets(manifest)

    def test_manifest_is_always_last(self):
        packages = {
            "b.zip": AssetSpec("b.zip", 2, SHA_B, "fullPackages[0]"),
            "a.zip": AssetSpec("a.zip", 1, SHA_A, "fullPackages[1]"),
        }
        launcher = AssetSpec("ChroniclesLauncher.exe", 3, SHA_C, "launcher")
        manifest = AssetSpec("manifest-dev.json", 4, SHA_A, "manifest-last")
        ordered = ordered_specs(packages, launcher, manifest)
        self.assertEqual(
            [item.name for item in ordered],
            [
                "a.zip",
                "b.zip",
                "ChroniclesLauncher.exe",
                "manifest-dev.json",
            ],
        )

    def test_unsafe_asset_names_are_rejected(self):
        for name in ("../bad.zip", "dir/bad.zip", "dir\\bad.zip", "bad\x00.zip"):
            with self.subTest(name=name), self.assertRaises(MirrorError):
                validate_asset_name(name)

    def test_largest_full_package_is_selected_deterministically(self):
        manifest = {
            "fullPackages": [
                package("small.zip", 10, SHA_A),
                package("z-largest.zip", 20, SHA_B),
                package("a-largest.zip", 20, SHA_C),
            ]
        }
        selected = largest_full_package(manifest)
        self.assertEqual(selected.name, "z-largest.zip")
        self.assertEqual(selected.size, 20)
        self.assertEqual(selected.kind, "fullPackages[1]")

    def test_largest_full_package_requires_at_least_one_full(self):
        with self.assertRaisesRegex(MirrorError, "no fullPackages"):
            largest_full_package({"fullPackages": []})

    def test_permanent_target_tag_is_the_cli_default(self):
        self.assertEqual(parse_args([]).gitea_tag, "dev-channel")

    def test_gitea_asset_parser_preserves_duplicate_names_for_recovery(self):
        release = {
            "assets": [
                {
                    "id": 1,
                    "name": "manifest-dev.json",
                    "size": 3,
                    "browser_download_url": "https://example.invalid/a/1",
                },
                {
                    "id": 2,
                    "name": "manifest-dev.json",
                    "size": 4,
                    "browser_download_url": "https://example.invalid/a/2",
                },
            ]
        }
        assets = GiteaReleaseClient.release_assets(release)
        self.assertEqual([item.id for item in assets["manifest-dev.json"]], [1, 2])

    def test_legacy_previous_manifest_remains_the_rollback_checkpoint(self):
        previous = target(7, "manifest-dev.json.previous-7-old-run")
        self.assertEqual(
            published_manifest_candidates(
                {previous.name: [previous]}, "manifest-dev.json"
            ),
            [previous],
        )


class ManifestProgressionTests(unittest.TestCase):
    @staticmethod
    def identity(version, content_hash=SHA_A, digest=SHA_B):
        return ManifestIdentity(version, int(version.rsplit(".", 1)[1]), content_hash, digest)

    def test_manifest_identity_requires_global_dev_version_format(self):
        identity = manifest_identity(
            {"version": "2026.09.05-dev.29", "contentHash": SHA_A},
            SHA_B,
            "manifest",
        )
        self.assertEqual(identity.dev_number, 29)
        with self.assertRaisesRegex(MirrorError, "YYYY.MM.DD-dev.N"):
            manifest_identity(
                {"version": "dev-2026.09.05.29", "contentHash": SHA_A},
                SHA_B,
                "manifest",
            )

    def test_global_dev_number_can_advance_across_date_change(self):
        source = self.identity("2026.09.06-dev.30")
        target_manifest = self.identity("2026.09.05-dev.29")
        self.assertEqual(
            validate_manifest_progression(
                source, [target_manifest], allow_rollback=False
            ),
            "advance",
        )

    def test_same_version_and_content_hash_is_idempotent(self):
        source = self.identity("2026.09.05-dev.29", SHA_A, SHA_B)
        target_manifest = self.identity("2026.09.05-dev.29", SHA_A, SHA_C)
        self.assertEqual(
            validate_manifest_progression(
                source, [target_manifest], allow_rollback=False
            ),
            "idempotent",
        )

    def test_lower_dev_number_is_rejected_even_with_later_date(self):
        source = self.identity("2026.09.10-dev.28")
        target_manifest = self.identity("2026.09.05-dev.29")
        with self.assertRaisesRegex(MirrorError, "rollback"):
            validate_manifest_progression(
                source, [target_manifest], allow_rollback=False
            )

    def test_same_dev_number_with_different_content_is_rejected(self):
        source = self.identity("2026.09.05-dev.29", SHA_A)
        target_manifest = self.identity("2026.09.05-dev.29", SHA_B)
        with self.assertRaisesRegex(MirrorError, "different contentHash"):
            validate_manifest_progression(
                source, [target_manifest], allow_rollback=False
            )

    def test_break_glass_requires_both_flag_and_environment_guard(self):
        with self.assertRaisesRegex(MirrorError, "also requires"):
            rollback_override_enabled(True, {})
        self.assertTrue(
            rollback_override_enabled(
                True, {mirror.ROLLBACK_GUARD_ENV: "true"}
            )
        )
        source = self.identity("2026.09.04-dev.28")
        target_manifest = self.identity("2026.09.05-dev.29")
        self.assertEqual(
            validate_manifest_progression(
                source, [target_manifest], allow_rollback=True
            ),
            "guarded-rollback",
        )

    def test_bootstrap_forces_existing_package_sha_verification(self):
        self.assertTrue(
            effective_existing_sha_verification(
                requested=False, probe=False, published_manifest_count=0
            )
        )
        self.assertFalse(
            effective_existing_sha_verification(
                requested=False, probe=False, published_manifest_count=1
            )
        )


class MutablePublicationTests(unittest.TestCase):
    def setUp(self):
        self.spec = AssetSpec("manifest-dev.json", 3, SHA_A, "manifest-last")
        self.old = target(1, self.spec.name)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.temp_root = Path(self.temp.name)
        self.source_path = self.temp_root / "source"
        self.source_path.write_bytes(b"new")

    @staticmethod
    def verification(events, valid_ids=None):
        valid_ids = valid_ids if valid_ids is not None else set()

        def verify(asset, spec, temp_root):
            events.append(("verify-id", asset.id, asset.name))
            if valid_ids and asset.id not in valid_ids:
                raise MirrorError("wrong SHA")

        def verify_canonical(client, tag, spec, temp_root):
            events.append(("verify-canonical", tag, spec.name))

        return verify, verify_canonical

    def run_replace(self, client, existing):
        verify, verify_canonical = self.verification(client.events)
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ), patch.object(mirror.time, "sleep"):
            replace_mutable_attachment(
                client=client,
                release_id=99,
                tag="dev-channel",
                existing=existing,
                source_path=self.source_path,
                spec=self.spec,
                temp_root=self.temp_root,
            )

    def test_existing_canonical_is_kept_until_new_id_is_verified(self):
        events = []
        client = FakeGiteaClient([self.old], events=events)
        self.run_replace(client, [self.old])

        new_id = max(client.assets)
        rename_index = events.index(("rename", new_id, self.spec.name))
        delete_old_index = events.index(("delete", self.old.id))
        first_verify = next(
            index
            for index, event in enumerate(events)
            if event[:2] == ("verify-id", new_id)
        )
        self.assertLess(first_verify, rename_index)
        self.assertLess(rename_index, delete_old_index)
        self.assertFalse(any(event[:2] == ("rename", self.old.id) for event in events))
        self.assertEqual(list(client.assets), [new_id])
        self.assertEqual(client.assets[new_id].name, self.spec.name)
        self.assertIn(("verify-canonical", "dev-channel", self.spec.name), events)

    def test_first_upload_is_anonymously_verified_before_canonical_rename(self):
        events = []
        client = FakeGiteaClient(events=events)
        self.run_replace(client, [])

        new_id = next(iter(client.assets))
        rename_index = events.index(("rename", new_id, self.spec.name))
        first_verify = next(
            index
            for index, event in enumerate(events)
            if event[:2] == ("verify-id", new_id)
        )
        self.assertLess(first_verify, rename_index)
        self.assertEqual(client.assets[new_id].name, self.spec.name)

    def test_timeout_after_successful_rename_is_reconciled_by_id(self):
        events = []
        client = FakeGiteaClient(
            [self.old], events=events, rename_failure="after"
        )
        self.run_replace(client, [self.old])

        self.assertNotIn(self.old.id, client.assets)
        canonical = [asset for asset in client.assets.values() if asset.name == self.spec.name]
        self.assertEqual(len(canonical), 1)

    def test_failed_rename_never_deletes_existing_canonical(self):
        events = []
        client = FakeGiteaClient(
            [self.old], events=events, rename_failure="before"
        )
        verify, verify_canonical = self.verification(events)
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ), patch.object(mirror.time, "sleep"):
            with self.assertRaisesRegex(MirrorError, "still named"):
                replace_mutable_attachment(
                    client=client,
                    release_id=99,
                    tag="dev-channel",
                    existing=[self.old],
                    source_path=self.source_path,
                    spec=self.spec,
                    temp_root=self.temp_root,
                )

        self.assertEqual(client.assets[self.old.id].name, self.spec.name)
        self.assertNotIn(("delete", self.old.id), events)
        pending = [
            asset
            for asset in client.assets.values()
            if asset.name.startswith(f"{self.spec.name}.pending-")
        ]
        self.assertEqual(len(pending), 1)

    def test_failed_staged_sha_never_deletes_existing_canonical(self):
        events = []
        client = FakeGiteaClient([self.old], events=events)

        def fail_new(asset, spec, temp_root):
            events.append(("verify-id", asset.id, asset.name))
            if asset.id != self.old.id:
                raise MirrorError("wrong SHA")

        with patch.object(mirror, "verify_public_target", side_effect=fail_new):
            with self.assertRaisesRegex(MirrorError, "wrong SHA"):
                replace_mutable_attachment(
                    client=client,
                    release_id=99,
                    tag="dev-channel",
                    existing=[self.old],
                    source_path=self.source_path,
                    spec=self.spec,
                    temp_root=self.temp_root,
                )

        self.assertEqual(set(client.assets), {self.old.id})
        self.assertNotIn(("delete", self.old.id), events)

    def test_timeout_after_successful_upload_is_reconciled(self):
        events = []
        client = FakeGiteaClient(
            [self.old], events=events, upload_failure="after"
        )
        self.run_replace(client, [self.old])
        self.assertEqual(len(client.assets), 1)
        self.assertNotIn(self.old.id, client.assets)

    def test_timeout_after_successful_delete_is_reconciled(self):
        events = []
        client = FakeGiteaClient(
            [self.old], events=events, delete_failure="after"
        )
        self.run_replace(client, [self.old])
        self.assertEqual(len(client.assets), 1)
        self.assertNotIn(self.old.id, client.assets)

    def test_post_rename_verification_failure_keeps_old_canonical(self):
        events = []
        client = FakeGiteaClient([self.old], events=events)
        new_verifications = 0

        def fail_second_new_check(asset, spec, temp_root):
            nonlocal new_verifications
            events.append(("verify-id", asset.id, asset.name))
            if asset.id != self.old.id:
                new_verifications += 1
                if new_verifications == 2:
                    raise MirrorError("post-rename network failure")

        with patch.object(
            mirror, "verify_public_target", side_effect=fail_second_new_check
        ):
            with self.assertRaisesRegex(MirrorError, "post-rename"):
                replace_mutable_attachment(
                    client=client,
                    release_id=99,
                    tag="dev-channel",
                    existing=[self.old],
                    source_path=self.source_path,
                    spec=self.spec,
                    temp_root=self.temp_root,
                )

        canonical_ids = {
            asset.id for asset in client.assets.values() if asset.name == self.spec.name
        }
        self.assertEqual(canonical_ids, {1, 2})
        self.assertNotIn(("delete", self.old.id), events)

    def test_replay_with_two_canonicals_keeps_verified_new_id(self):
        events = []
        new = target(2, self.spec.name)
        client = FakeGiteaClient([self.old, new], events=events)
        verify, verify_canonical = self.verification(events, valid_ids={new.id})
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ):
            result = sync_asset(
                spec=self.spec,
                source=SourceAsset(self.spec.name, 3, SHA_A, "https://source.invalid"),
                mutable=True,
                verify_existing_sha=True,
                client=client,
                release_id=99,
                tag="dev-channel",
                existing_assets=client.grouped(),
                temp_root=self.temp_root,
            )

        self.assertEqual(result, "reconciled-existing")
        self.assertEqual(set(client.assets), {new.id})
        self.assertIn(("delete", self.old.id), events)

    def test_replay_with_two_valid_canonicals_keeps_highest_id(self):
        events = []
        new = target(2, self.spec.name)
        client = FakeGiteaClient([self.old, new], events=events)
        verify, verify_canonical = self.verification(events)
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ):
            sync_asset(
                spec=self.spec,
                source=SourceAsset(self.spec.name, 3, SHA_A, "https://source.invalid"),
                mutable=True,
                verify_existing_sha=True,
                client=client,
                release_id=99,
                tag="dev-channel",
                existing_assets=client.grouped(),
                temp_root=self.temp_root,
            )

        self.assertEqual(set(client.assets), {new.id})

    def test_single_verified_canonical_is_never_deleted(self):
        events = []
        client = FakeGiteaClient([self.old], events=events)
        verify, verify_canonical = self.verification(events)
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ):
            result = sync_asset(
                spec=self.spec,
                source=SourceAsset(self.spec.name, 3, SHA_A, "https://source.invalid"),
                mutable=True,
                verify_existing_sha=True,
                client=client,
                release_id=99,
                tag="dev-channel",
                existing_assets=client.grouped(),
                temp_root=self.temp_root,
            )

        self.assertEqual(result, "verified-existing")
        self.assertFalse(any(event[0] == "delete" for event in events))

    def test_replay_reuses_verified_pending_instead_of_uploading_again(self):
        events = []
        pending = target(
            2, f"{self.spec.name}.pending-{self.spec.sha256[:12]}-old-run"
        )
        client = FakeGiteaClient([self.old, pending], events=events)
        verify, verify_canonical = self.verification(events, valid_ids={pending.id})
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ):
            result = sync_asset(
                spec=self.spec,
                source=SourceAsset(self.spec.name, 3, SHA_A, "https://source.invalid"),
                mutable=True,
                verify_existing_sha=True,
                client=client,
                release_id=99,
                tag="dev-channel",
                existing_assets=client.grouped(),
                temp_root=self.temp_root,
            )

        self.assertEqual(result, "replaced")
        self.assertFalse(any(event[0] == "upload" for event in events))
        self.assertEqual(set(client.assets), {pending.id})

    def test_legacy_previous_is_restored_before_pending_handover(self):
        events = []
        previous = target(1, f"{self.spec.name}.previous-1-old-run")
        pending = target(
            2, f"{self.spec.name}.pending-{self.spec.sha256[:12]}-old-run"
        )
        client = FakeGiteaClient([previous, pending], events=events)
        verify, verify_canonical = self.verification(events, valid_ids={pending.id})
        with patch.object(mirror, "verify_public_target", side_effect=verify), patch.object(
            mirror, "verify_public_canonical", side_effect=verify_canonical
        ):
            sync_asset(
                spec=self.spec,
                source=SourceAsset(self.spec.name, 3, SHA_A, "https://source.invalid"),
                mutable=True,
                verify_existing_sha=True,
                client=client,
                release_id=99,
                tag="dev-channel",
                existing_assets=client.grouped(),
                temp_root=self.temp_root,
            )

        renames = [event for event in events if event[0] == "rename"]
        self.assertEqual(renames[0], ("rename", previous.id, self.spec.name))
        self.assertFalse(any(event[0] == "upload" for event in events))
        self.assertEqual(set(client.assets), {pending.id})


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / "asset.bin"

    def test_valid_content_range_resumes_partial_download(self):
        partial = self.destination.with_name(self.destination.name + ".part")
        partial.write_bytes(b"abc")
        response = FakeResponse(
            b"def", 206, {"Content-Range": "bytes 3-5/6"}
        )
        with patch.object(mirror.urllib.request, "urlopen", return_value=response):
            size, digest = download_file(
                "https://example.invalid/asset",
                self.destination,
                expected_size=6,
                expected_sha256=hashlib.sha256(b"abcdef").hexdigest(),
                attempts=1,
            )
        self.assertEqual(size, 6)
        self.assertEqual(digest, hashlib.sha256(b"abcdef").hexdigest())
        self.assertEqual(self.destination.read_bytes(), b"abcdef")

    def test_invalid_content_range_is_rejected_and_partial_is_retired(self):
        partial = self.destination.with_name(self.destination.name + ".part")
        partial.write_bytes(b"abc")
        response = FakeResponse(
            b"def", 206, {"Content-Range": "bytes 2-5/6"}
        )
        with patch.object(mirror.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(MirrorError, "Content-Range"):
                download_file(
                    "https://example.invalid/asset",
                    self.destination,
                    expected_size=6,
                    expected_sha256=None,
                    attempts=1,
                )
        self.assertFalse(partial.exists())

    def test_http_exception_is_retried(self):
        response = FakeResponse(b"abc", 200)
        with patch.object(
            mirror.urllib.request,
            "urlopen",
            side_effect=[http.client.IncompleteRead(b""), response],
        ), patch.object(mirror.time, "sleep"):
            size, _ = download_file(
                "https://example.invalid/asset",
                self.destination,
                expected_size=3,
                expected_sha256=hashlib.sha256(b"abc").hexdigest(),
                attempts=2,
            )
        self.assertEqual(size, 3)


class WorkflowSafetyTests(unittest.TestCase):
    def test_non_default_source_tag_is_rejected_before_write_mode_network(self):
        with patch.dict(
            os.environ, {mirror.ROLLBACK_GUARD_ENV: "false"}, clear=False
        ):
            with self.assertRaisesRegex(MirrorError, "persistent source tag"):
                mirror.main(["--github-tag", "older-release"])

    def test_dry_run_drops_gitea_token_and_performs_no_write(self):
        manifest_bytes = json.dumps(
            {
                "version": "2026.09.05-dev.29",
                "contentHash": SHA_A,
                "fullPackages": [],
            }
        ).encode("utf-8")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

        class FakeSourceClient:
            def __init__(self):
                self.assets = {
                    "manifest-dev.json": SourceAsset(
                        "manifest-dev.json",
                        len(manifest_bytes),
                        manifest_digest,
                        "https://source.invalid/manifest",
                    ),
                    "ChroniclesLauncher.exe": SourceAsset(
                        "ChroniclesLauncher.exe", 3, SHA_B, "https://source.invalid/launcher"
                    ),
                }

            def load(self):
                return None

            def require(self, spec):
                return self.assets[spec.name]

        class FakeTargetClient:
            def require_public_repo(self):
                return {"private": False}

            def get_release(self, tag):
                return None

            def require_token(self):
                raise AssertionError("dry-run attempted to enter a write path")

        source = FakeSourceClient()
        target_client = FakeTargetClient()

        def fake_download(url, destination, **kwargs):
            destination.write_bytes(manifest_bytes)
            return len(manifest_bytes), manifest_digest

        with patch.object(mirror, "GitHubReleaseClient", return_value=source), patch.object(
            mirror, "GiteaReleaseClient", return_value=target_client
        ) as target_constructor, patch.object(
            mirror, "download_file", side_effect=fake_download
        ), patch.dict(os.environ, {"GITEA_TOKEN": "must-not-enter-plan"}):
            self.assertEqual(mirror.main(["--dry-run"]), 0)

        self.assertIsNone(target_constructor.call_args.args[2])

    def test_workflow_keeps_plan_secretless_and_pins_actions(self):
        workflow = (
            Path(__file__).parents[1]
            / ".github"
            / "workflows"
            / "mirror-release-to-gitea.yml"
        ).read_text(encoding="utf-8")
        plan = workflow.split("- name: Plan manifest-selected assets", 1)[1].split(
            "- name: Mirror manifest-selected assets", 1
        )[0]
        self.assertNotIn("GITEA_TOKEN", plan)
        self.assertNotIn("source_tag:", workflow)
        self.assertIn("--github-tag dev-2026.08.26.1", workflow)
        for action in ("actions/checkout", "actions/setup-python", "actions/upload-artifact"):
            self.assertRegex(workflow, rf"uses: {action}@[0-9a-f]{{40}}")


if __name__ == "__main__":
    unittest.main()
