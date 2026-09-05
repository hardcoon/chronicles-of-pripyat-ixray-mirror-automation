import unittest

from mirror_release_assets import (
    AssetSpec,
    MirrorError,
    collect_manifest_assets,
    largest_full_package,
    ordered_specs,
    parse_args,
    validate_asset_name,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def package(name: str, size: int, digest: str):
    return {"assetName": name, "size": size, "sha256": digest, "files": []}


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
        self.assertEqual([item.name for item in ordered], [
            "a.zip",
            "b.zip",
            "ChroniclesLauncher.exe",
            "manifest-dev.json",
        ])

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


if __name__ == "__main__":
    unittest.main()
