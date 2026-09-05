#!/usr/bin/env python3
"""Mirror the launcher release from GitHub to a public Gitea repository.

The script deliberately treats ``manifest-dev.json`` as the commit record for
the mirror.  Every asset referenced by the manifest, including packages from
``deltaTransitions``, is present and verified before the canonical manifest is
switched on Gitea.

Only Python's standard library is used.  Transfers are streamed through the
CI runner one file at a time, so the runner never needs space for the complete
game.  This is server-to-server transfer when executed by GitHub Actions; the
developer workstation is not involved.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


USER_AGENT = "chronicles-of-pripyat-gitea-mirror/1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_SOURCE_REPO = "hardcoon/chronicles-of-pripyat-ixray"
DEFAULT_SOURCE_TAG = "dev-2026.08.26.1"
DEFAULT_TARGET_REPO = "hardcoon/chronicles-of-pripyat-ixray-downloads"
DEFAULT_GITEA_URL = "https://gitea.com"
DEFAULT_TARGET_TAG = "dev-channel"
DEFAULT_MANIFEST_NAME = "manifest-dev.json"
DEFAULT_LAUNCHER_NAME = "ChroniclesLauncher.exe"
PACKAGE_FIELDS = ("fullPackages", "deltaPackages", "initialPackages")


class MirrorError(RuntimeError):
    """A safe, user-actionable mirror failure."""


@dataclasses.dataclass(frozen=True)
class AssetSpec:
    name: str
    size: int
    sha256: str
    kind: str


@dataclasses.dataclass(frozen=True)
class SourceAsset:
    name: str
    size: int
    sha256: str | None
    download_url: str


@dataclasses.dataclass(frozen=True)
class TargetAsset:
    id: int
    name: str
    size: int
    download_url: str


def normalize_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MirrorError(f"{field} must be a SHA-256 string")
    value = value.strip().lower()
    if value.startswith("sha256:"):
        value = value[7:]
    if not SHA256_RE.fullmatch(value):
        raise MirrorError(f"{field} is not a valid SHA-256 digest")
    return value


def validate_asset_name(value: Any, field: str = "assetName") -> str:
    if not isinstance(value, str) or not value:
        raise MirrorError(f"{field} must be a non-empty string")
    if value in {".", ".."} or Path(value).name != value:
        raise MirrorError(f"{field} must be a plain filename: {value!r}")
    if any(ord(char) < 32 for char in value) or any(
        char in value for char in ('/', '\\', '"', "\x00")
    ):
        raise MirrorError(f"{field} contains unsafe characters: {value!r}")
    return value


def normalize_size(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise MirrorError(f"{field} must be an integer")
    try:
        size = int(value)
    except (TypeError, ValueError) as exc:
        raise MirrorError(f"{field} must be an integer") from exc
    if size <= 0:
        raise MirrorError(f"{field} must be greater than zero")
    return size


def as_object_list(value: Any, field: str) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, list):
        raise MirrorError(f"{field} must be an array")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise MirrorError(f"{field}[{index}] must be an object")
        result.append(item)
    return result


def add_spec(target: dict[str, AssetSpec], spec: AssetSpec) -> None:
    previous = target.get(spec.name)
    if previous is None:
        target[spec.name] = spec
        return
    if previous.size != spec.size or previous.sha256 != spec.sha256:
        raise MirrorError(
            "manifest assigns conflicting size/SHA-256 values to "
            f"{spec.name!r} ({previous.kind} versus {spec.kind})"
        )


def package_spec(package: Mapping[str, Any], field: str) -> AssetSpec:
    return AssetSpec(
        name=validate_asset_name(package.get("assetName"), f"{field}.assetName"),
        size=normalize_size(package.get("size"), f"{field}.size"),
        sha256=normalize_sha256(package.get("sha256"), f"{field}.sha256"),
        kind=field,
    )


def collect_manifest_assets(manifest: Mapping[str, Any]) -> dict[str, AssetSpec]:
    """Return all package assets supported by this manifest.

    The current direct transition remains represented by the top-level
    ``deltaPackages`` field.  New launchers additionally consume
    ``deltaTransitions[*].packages``.  Exact duplicate references are fine;
    conflicting references fail closed.
    """

    result: dict[str, AssetSpec] = {}
    for field in PACKAGE_FIELDS:
        for index, package in enumerate(as_object_list(manifest.get(field), field)):
            add_spec(result, package_spec(package, f"{field}[{index}]"))

    transitions = as_object_list(manifest.get("deltaTransitions"), "deltaTransitions")
    if len(transitions) > 128:
        raise MirrorError("deltaTransitions exceeds the safety limit of 128")
    for transition_index, transition in enumerate(transitions):
        packages_field = f"deltaTransitions[{transition_index}].packages"
        for package_index, package in enumerate(
            as_object_list(transition.get("packages"), packages_field)
        ):
            add_spec(
                result,
                package_spec(package, f"{packages_field}[{package_index}]"),
            )
    return result


def largest_full_package(manifest: Mapping[str, Any]) -> AssetSpec:
    """Return the largest current clean-install package deterministically."""

    packages = [
        package_spec(package, f"fullPackages[{index}]")
        for index, package in enumerate(
            as_object_list(manifest.get("fullPackages"), "fullPackages")
        )
    ]
    if not packages:
        raise MirrorError("manifest has no fullPackages for the large-upload probe")
    return max(packages, key=lambda item: (item.size, item.name.casefold()))


def ordered_specs(
    packages: Mapping[str, AssetSpec], launcher: AssetSpec, manifest: AssetSpec
) -> list[AssetSpec]:
    """Provide a deterministic order with the manifest strictly last."""

    values = sorted(packages.values(), key=lambda item: item.name.casefold())
    values.append(launcher)
    values.append(manifest)
    return values


def split_repo(value: str, field: str) -> tuple[str, str]:
    parts = value.strip().split("/")
    if len(parts) != 2 or not all(parts):
        raise MirrorError(f"{field} must have OWNER/REPO form")
    allowed = re.compile(r"^[A-Za-z0-9_.-]+$")
    if not all(allowed.fullmatch(part) for part in parts):
        raise MirrorError(f"{field} contains unsupported characters")
    return parts[0], parts[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: Mapping[str, Any] | None = None,
    expected: Sequence[int] = (200,),
) -> tuple[int, Any]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url, data=data, headers=request_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            status = response.status
            payload = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read()
    if status not in expected:
        detail = payload.decode("utf-8", errors="replace")[:1000]
        raise MirrorError(f"{method} {url} returned HTTP {status}: {detail}")
    if not payload:
        return status, None
    try:
        return status, json.loads(payload)
    except json.JSONDecodeError as exc:
        raise MirrorError(f"{method} {url} did not return valid JSON") from exc


def download_file(
    url: str,
    destination: Path,
    *,
    expected_size: int | None,
    expected_sha256: str | None,
    attempts: int = 6,
) -> tuple[int, str]:
    """Download with Range resume, then verify size and SHA-256."""

    partial = destination.with_name(destination.name + ".part")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()

    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            offset = partial.stat().st_size if partial.exists() else 0
            headers = {"User-Agent": USER_AGENT, "Accept": "application/octet-stream"}
            if offset:
                headers["Range"] = f"bytes={offset}-"
            request = urllib.request.Request(url, headers=headers)
            try:
                response = urllib.request.urlopen(request, timeout=180)
            except urllib.error.HTTPError as exc:
                if exc.code == 416 and expected_size is not None and offset == expected_size:
                    response = None
                else:
                    raise

            if response is not None:
                with response:
                    status = response.status
                    if offset and status != 206:
                        offset = 0
                        mode = "wb"
                    else:
                        mode = "ab" if offset else "wb"
                    with partial.open(mode) as output:
                        shutil.copyfileobj(response, output, length=8 * 1024 * 1024)

            size = partial.stat().st_size
            if expected_size is not None and size != expected_size:
                raise MirrorError(
                    f"downloaded size mismatch for {destination.name}: "
                    f"expected {expected_size}, got {size}"
                )
            digest = sha256_file(partial)
            if expected_sha256 is not None and digest != expected_sha256:
                raise MirrorError(
                    f"downloaded SHA-256 mismatch for {destination.name}: "
                    f"expected {expected_sha256}, got {digest}"
                )
            os.replace(partial, destination)
            return size, digest
        except (OSError, urllib.error.URLError, MirrorError) as exc:
            last_error = exc
            if isinstance(exc, MirrorError) and "SHA-256 mismatch" in str(exc):
                partial.unlink(missing_ok=True)
                break
            if attempt + 1 < attempts:
                time.sleep(min(2**attempt, 20))
    raise MirrorError(f"download failed for {url}: {last_error}")


class GitHubReleaseClient:
    def __init__(self, repo: str, tag: str, token: str | None) -> None:
        self.owner, self.repo = split_repo(repo, "--github-repo")
        self.tag = tag
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.release: Mapping[str, Any] | None = None
        self.assets: dict[str, SourceAsset] = {}

    def load(self) -> None:
        encoded_tag = urllib.parse.quote(self.tag, safe="")
        _, release = request_json(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/releases/tags/{encoded_tag}",
            headers=self.headers,
        )
        if not isinstance(release, Mapping) or release.get("draft"):
            raise MirrorError("source GitHub release is missing or still a draft")
        self.release = release
        release_id = int(release["id"])
        records: list[Mapping[str, Any]] = []
        for page in range(1, 100):
            _, payload = request_json(
                "https://api.github.com/repos/"
                f"{self.owner}/{self.repo}/releases/{release_id}/assets"
                f"?per_page=100&page={page}",
                headers=self.headers,
            )
            if not isinstance(payload, list):
                raise MirrorError("GitHub release assets response is not an array")
            records.extend(item for item in payload if isinstance(item, Mapping))
            if len(payload) < 100:
                break
        else:
            raise MirrorError("GitHub release asset pagination exceeded 9900 entries")

        assets: dict[str, SourceAsset] = {}
        for record in records:
            name = validate_asset_name(record.get("name"), "GitHub asset name")
            if name in assets:
                raise MirrorError(f"duplicate source GitHub asset name: {name}")
            digest_value = record.get("digest")
            digest = (
                normalize_sha256(digest_value, f"GitHub asset {name} digest")
                if digest_value
                else None
            )
            assets[name] = SourceAsset(
                name=name,
                size=normalize_size(record.get("size"), f"GitHub asset {name} size"),
                sha256=digest,
                download_url=str(record.get("browser_download_url") or ""),
            )
        self.assets = assets

    def require(self, spec: AssetSpec) -> SourceAsset:
        source = self.assets.get(spec.name)
        if source is None:
            raise MirrorError(f"source GitHub release lacks required asset {spec.name}")
        if source.size != spec.size:
            raise MirrorError(
                f"GitHub size for {spec.name} is {source.size}, manifest says {spec.size}"
            )
        if source.sha256 is not None and source.sha256 != spec.sha256:
            raise MirrorError(
                f"GitHub digest for {spec.name} disagrees with the manifest"
            )
        if not source.download_url.startswith("https://"):
            raise MirrorError(f"GitHub asset {spec.name} lacks a safe HTTPS URL")
        return source


class GiteaReleaseClient:
    def __init__(self, base_url: str, repo: str, token: str | None) -> None:
        parsed = urllib.parse.urlsplit(base_url.rstrip("/"))
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
            raise MirrorError("--gitea-url must be an HTTPS server root URL")
        self.base_url = f"https://{parsed.netloc}"
        self.owner, self.repo = split_repo(repo, "--gitea-repo")
        self.token = token

    @property
    def api_root(self) -> str:
        return f"{self.base_url}/api/v1/repos/{self.owner}/{self.repo}"

    @property
    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"token {self.token}"} if self.token else {}

    def require_public_repo(self) -> Mapping[str, Any]:
        _, repo = request_json(self.api_root, headers=self.auth_headers)
        if not isinstance(repo, Mapping):
            raise MirrorError("Gitea repository response is invalid")
        if bool(repo.get("private")):
            raise MirrorError("Gitea mirror repository must be public")
        return repo

    def get_release(self, tag: str) -> Mapping[str, Any] | None:
        encoded_tag = urllib.parse.quote(tag, safe="")
        status, release = request_json(
            f"{self.api_root}/releases/tags/{encoded_tag}",
            headers=self.auth_headers,
            expected=(200, 404),
        )
        if status == 404:
            return None
        if not isinstance(release, Mapping):
            raise MirrorError("Gitea release response is invalid")
        return release

    def create_release(self, tag: str, version: str) -> Mapping[str, Any]:
        self.require_token()
        _, release = request_json(
            f"{self.api_root}/releases",
            method="POST",
            headers=self.auth_headers,
            body={
                "tag_name": tag,
                "target_commitish": "main",
                "name": "Chronicles of Pripyat update mirror",
                "body": (
                    "Automated download mirror. The canonical metadata is "
                    f"manifest-dev.json ({version})."
                ),
                "draft": False,
                "prerelease": True,
            },
            expected=(201,),
        )
        if not isinstance(release, Mapping):
            raise MirrorError("Gitea create-release response is invalid")
        return release

    def require_token(self) -> str:
        if not self.token:
            raise MirrorError("Gitea write operation requires the configured token")
        return self.token

    @staticmethod
    def release_assets(release: Mapping[str, Any]) -> dict[str, TargetAsset]:
        result: dict[str, TargetAsset] = {}
        raw_assets = release.get("assets") or []
        if not isinstance(raw_assets, list):
            raise MirrorError("Gitea release assets field is invalid")
        for raw in raw_assets:
            if not isinstance(raw, Mapping):
                raise MirrorError("Gitea release contains an invalid asset record")
            name = validate_asset_name(raw.get("name"), "Gitea asset name")
            if name in result:
                raise MirrorError(f"duplicate Gitea attachment name: {name}")
            result[name] = TargetAsset(
                id=int(raw["id"]),
                name=name,
                size=int(raw["size"]),
                download_url=str(raw.get("browser_download_url") or ""),
            )
        return result

    def refresh_assets(self, tag: str) -> tuple[Mapping[str, Any], dict[str, TargetAsset]]:
        release = self.get_release(tag)
        if release is None:
            raise MirrorError("Gitea release disappeared during synchronization")
        return release, self.release_assets(release)

    def upload(self, release_id: int, path: Path, target_name: str) -> TargetAsset:
        token = self.require_token()
        target_name = validate_asset_name(target_name, "target attachment name")
        boundary = "------------------------" + uuid.uuid4().hex
        preamble = (
            f"--{boundary}\r\n"
            "Content-Disposition: form-data; name=\"attachment\"; "
            f"filename=\"{path.name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("ascii")
        epilogue = f"\r\n--{boundary}--\r\n".encode("ascii")
        size = path.stat().st_size
        endpoint = (
            f"{self.api_root}/releases/{release_id}/assets?"
            + urllib.parse.urlencode({"name": target_name})
        )
        parsed = urllib.parse.urlsplit(endpoint)
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=600,
            context=ssl.create_default_context(),
        )
        try:
            connection.putrequest("POST", parsed.path + "?" + parsed.query)
            connection.putheader("User-Agent", USER_AGENT)
            connection.putheader("Accept", "application/json")
            connection.putheader("Authorization", f"token {token}")
            connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
            connection.putheader("Content-Length", str(len(preamble) + size + len(epilogue)))
            connection.endheaders()
            connection.send(preamble)
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                    connection.send(chunk)
            connection.send(epilogue)
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        if response.status != 201:
            detail = payload.decode("utf-8", errors="replace")[:1000]
            raise MirrorError(
                f"Gitea upload of {target_name} returned HTTP {response.status}: {detail}"
            )
        try:
            raw = json.loads(payload)
            uploaded = TargetAsset(
                id=int(raw["id"]),
                name=validate_asset_name(raw["name"], "uploaded asset name"),
                size=int(raw["size"]),
                download_url=str(raw["browser_download_url"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MirrorError("Gitea upload returned an invalid attachment record") from exc
        if uploaded.name != target_name or uploaded.size != size:
            raise MirrorError(
                f"Gitea upload metadata mismatch for {target_name}: "
                f"name={uploaded.name!r}, size={uploaded.size}"
            )
        return uploaded

    def rename(self, release_id: int, asset_id: int, name: str) -> TargetAsset:
        self.require_token()
        name = validate_asset_name(name, "renamed attachment")
        _, raw = request_json(
            f"{self.api_root}/releases/{release_id}/assets/{asset_id}",
            method="PATCH",
            headers=self.auth_headers,
            body={"name": name},
            expected=(200, 201),
        )
        if not isinstance(raw, Mapping):
            raise MirrorError("Gitea rename response is invalid")
        return TargetAsset(
            id=int(raw["id"]),
            name=str(raw["name"]),
            size=int(raw["size"]),
            download_url=str(raw["browser_download_url"]),
        )

    def delete(self, release_id: int, asset_id: int) -> None:
        self.require_token()
        request_json(
            f"{self.api_root}/releases/{release_id}/assets/{asset_id}",
            method="DELETE",
            headers=self.auth_headers,
            expected=(204,),
        )


def verify_public_target(asset: TargetAsset, spec: AssetSpec, temp_root: Path) -> None:
    if not asset.download_url.startswith("https://"):
        raise MirrorError(f"Gitea attachment {asset.name} has no public HTTPS URL")
    destination = temp_root / f"verify-{asset.id}-{spec.name}"
    try:
        download_file(
            asset.download_url,
            destination,
            expected_size=spec.size,
            expected_sha256=spec.sha256,
        )
    finally:
        destination.unlink(missing_ok=True)


def download_source(
    source: SourceAsset, spec: AssetSpec, temp_root: Path
) -> Path:
    destination = temp_root / f"source-{spec.name}"
    download_file(
        source.download_url,
        destination,
        expected_size=spec.size,
        expected_sha256=spec.sha256,
    )
    return destination


def replace_mutable_attachment(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    existing: TargetAsset,
    source_path: Path,
    spec: AssetSpec,
    temp_root: Path,
) -> None:
    """Stage, verify, switch, verify again, and then remove the old asset."""

    suffix = f"{spec.sha256[:12]}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    pending_name = validate_asset_name(f"{spec.name}.pending-{suffix}")
    backup_name = validate_asset_name(f"{spec.name}.previous-{existing.id}-{suffix}")
    failed_name = validate_asset_name(f"{spec.name}.failed-{suffix}")
    pending: TargetAsset | None = None
    renamed_old = False
    canonical_new: TargetAsset | None = None
    try:
        pending = client.upload(release_id, source_path, pending_name)
        verify_public_target(pending, spec, temp_root)
        client.rename(release_id, existing.id, backup_name)
        renamed_old = True
        canonical_new = client.rename(release_id, pending.id, spec.name)
        verify_public_target(canonical_new, spec, temp_root)
    except Exception:
        if canonical_new is not None:
            try:
                client.rename(release_id, canonical_new.id, failed_name)
            except Exception:
                pass
        elif pending is not None:
            try:
                client.delete(release_id, pending.id)
            except Exception:
                pass
        if renamed_old:
            try:
                client.rename(release_id, existing.id, spec.name)
            except Exception as rollback_error:
                raise MirrorError(
                    f"failed to switch {spec.name} and rollback also failed: "
                    f"{rollback_error}"
                )
        raise
    try:
        client.delete(release_id, existing.id)
    except Exception as exc:
        print(
            f"WARNING: canonical {spec.name} is valid, but stale backup "
            f"attachment {backup_name} could not be removed: {exc}",
            file=sys.stderr,
        )


def sync_asset(
    *,
    spec: AssetSpec,
    source: SourceAsset,
    mutable: bool,
    verify_existing_sha: bool,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    existing_assets: Mapping[str, TargetAsset],
    temp_root: Path,
) -> str:
    existing = existing_assets.get(spec.name)
    if existing is not None and existing.size == spec.size:
        if mutable or verify_existing_sha:
            try:
                verify_public_target(existing, spec, temp_root)
                print(f"verified existing: {spec.name}")
                return "verified-existing"
            except MirrorError:
                if not mutable:
                    raise
        else:
            # Immutable package filenames are content/version specific.  A first
            # bootstrap should use --verify-existing-sha; later jobs may trust
            # the size of assets that a previous successful job verified.
            print(f"reused immutable asset by name/size: {spec.name}")
            return "reused-existing"
    elif existing is not None and not mutable:
        raise MirrorError(
            f"immutable Gitea asset {spec.name} has size {existing.size}; "
            f"expected {spec.size}. Refusing destructive replacement."
        )

    source_path = download_source(source, spec, temp_root)
    try:
        if existing is not None:
            replace_mutable_attachment(
                client=client,
                release_id=release_id,
                tag=tag,
                existing=existing,
                source_path=source_path,
                spec=spec,
                temp_root=temp_root,
            )
            print(f"replaced and verified: {spec.name}")
            return "replaced"

        uploaded: TargetAsset | None = None
        try:
            uploaded = client.upload(release_id, source_path, spec.name)
            verify_public_target(uploaded, spec, temp_root)
        except Exception:
            if uploaded is not None:
                try:
                    client.delete(release_id, uploaded.id)
                except Exception:
                    pass
            raise
        print(f"uploaded and verified: {spec.name}")
        return "uploaded"
    finally:
        source_path.unlink(missing_ok=True)


def write_json(path: Path | None, value: Mapping[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-repo", default=DEFAULT_SOURCE_REPO)
    parser.add_argument("--github-tag", default=DEFAULT_SOURCE_TAG)
    parser.add_argument("--gitea-url", default=DEFAULT_GITEA_URL)
    parser.add_argument("--gitea-repo", default=DEFAULT_TARGET_REPO)
    parser.add_argument("--gitea-tag", default=DEFAULT_TARGET_TAG)
    parser.add_argument("--manifest-name", default=DEFAULT_MANIFEST_NAME)
    parser.add_argument("--launcher-name", default=DEFAULT_LAUNCHER_NAME)
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--gitea-token-env", default="GITEA_TOKEN")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--probe-largest-full",
        action="store_true",
        help=(
            "Upload and anonymously verify only the largest current full package. "
            "The asset keeps its canonical name in the permanent target release, "
            "so a successful probe is reused by the later bootstrap. Does not "
            "publish the launcher or manifest. Combine with --dry-run to plan only."
        ),
    )
    parser.add_argument(
        "--verify-existing-sha",
        action="store_true",
        help="Download/hash every existing immutable Gitea package (use for bootstrap audit)",
    )
    parser.add_argument("--max-assets", type=int, default=512)
    parser.add_argument("--max-asset-bytes", type=int, default=2_100_000_000)
    parser.add_argument("--max-total-bytes", type=int, default=35_000_000_000)
    parser.add_argument("--plan-out", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    manifest_name = validate_asset_name(args.manifest_name, "--manifest-name")
    launcher_name = validate_asset_name(args.launcher_name, "--launcher-name")
    github_token = os.environ.get(args.github_token_env) or None
    gitea_token = os.environ.get(args.gitea_token_env) or None

    source_client = GitHubReleaseClient(args.github_repo, args.github_tag, github_token)
    source_client.load()
    manifest_source = source_client.assets.get(manifest_name)
    launcher_source = source_client.assets.get(launcher_name)
    if manifest_source is None:
        raise MirrorError("source Release must contain the manifest asset")
    if not args.probe_largest_full and launcher_source is None:
        raise MirrorError("source Release must contain the launcher asset")

    with tempfile.TemporaryDirectory(prefix="cop-gitea-mirror-") as temp_name:
        temp_root = Path(temp_name)
        manifest_path = temp_root / manifest_name
        _, manifest_digest = download_file(
            manifest_source.download_url,
            manifest_path,
            expected_size=manifest_source.size,
            expected_sha256=manifest_source.sha256,
        )
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MirrorError("manifest-dev.json is not valid UTF-8 JSON") from exc
        if not isinstance(manifest, Mapping):
            raise MirrorError("manifest-dev.json root must be an object")
        version = str(manifest.get("version") or "").strip()
        if not version:
            raise MirrorError("manifest.version must be a non-empty string")
        content_hash = normalize_sha256(
            manifest.get("contentHash"), "manifest.contentHash"
        )

        package_specs = collect_manifest_assets(manifest)
        for spec in package_specs.values():
            source_client.require(spec)
        manifest_spec = AssetSpec(
            manifest_name, manifest_source.size, manifest_digest, "manifest-last"
        )
        if args.probe_largest_full:
            probe_spec = largest_full_package(manifest)
            source_client.require(probe_spec)
            specs = [probe_spec]
            operation = "largest-full-probe"
        else:
            assert launcher_source is not None
            if launcher_source.sha256 is None:
                launcher_path = temp_root / f"probe-{launcher_name}"
                try:
                    _, launcher_digest = download_file(
                        launcher_source.download_url,
                        launcher_path,
                        expected_size=launcher_source.size,
                        expected_sha256=None,
                    )
                finally:
                    launcher_path.unlink(missing_ok=True)
            else:
                launcher_digest = launcher_source.sha256

            launcher_spec = AssetSpec(
                launcher_name, launcher_source.size, launcher_digest, "launcher"
            )
            specs = ordered_specs(package_specs, launcher_spec, manifest_spec)
            operation = "mirror"
        if len(specs) > args.max_assets:
            raise MirrorError(
                f"desired mirror has {len(specs)} assets; limit is {args.max_assets}"
            )
        for spec in specs:
            if spec.size > args.max_asset_bytes:
                raise MirrorError(
                    f"{spec.name} is {spec.size} bytes; per-asset safety limit is "
                    f"{args.max_asset_bytes}"
                )
        total_size = sum(spec.size for spec in specs)
        if total_size > args.max_total_bytes:
            raise MirrorError(
                f"desired mirror is {total_size} bytes; total safety limit is "
                f"{args.max_total_bytes}"
            )

        target_client = GiteaReleaseClient(args.gitea_url, args.gitea_repo, gitea_token)
        target_client.require_public_repo()
        target_release = target_client.get_release(args.gitea_tag)
        target_assets = (
            target_client.release_assets(target_release) if target_release else {}
        )

        actions: list[dict[str, Any]] = []
        for spec in specs:
            current = target_assets.get(spec.name)
            if current is None:
                action = "upload"
            elif current.size != spec.size:
                action = "replace" if spec.kind in {"launcher", "manifest-last"} else "conflict"
            elif (
                spec.kind in {"launcher", "manifest-last"}
                or args.verify_existing_sha
                or args.probe_largest_full
            ):
                action = "verify-or-replace" if spec.kind in {"launcher", "manifest-last"} else "verify"
            else:
                action = "reuse-by-name-size"
            actions.append(
                {
                    "name": spec.name,
                    "kind": spec.kind,
                    "size": spec.size,
                    "sha256": spec.sha256,
                    "action": action,
                }
            )

        plan = {
            "operation": operation,
            "source": {
                "repository": args.github_repo,
                "tag": args.github_tag,
                "manifestSha256": manifest_digest,
            },
            "target": {
                "baseUrl": args.gitea_url,
                "repository": args.gitea_repo,
                "tag": args.gitea_tag,
                "releaseExists": target_release is not None,
            },
            "version": version,
            "contentHash": content_hash,
            "assetCount": len(specs),
            "packageAssetCount": len(specs) if args.probe_largest_full else len(package_specs),
            "totalBytes": total_size,
            "manifestWillChange": not args.probe_largest_full,
            "manifestIsLast": (
                specs[-1].name == manifest_name if not args.probe_largest_full else False
            ),
            "actions": actions,
        }
        write_json(args.plan_out, plan)
        print(
            f"plan: operation={operation}, version={version}, "
            f"packages={plan['packageAssetCount']}, "
            f"assets={len(specs)}, totalBytes={total_size}, "
            f"manifestWillChange={plan['manifestWillChange']}"
        )
        for action in actions:
            print(f"  {action['action']:22} {action['size']:12} {action['name']}")
        if any(action["action"] == "conflict" for action in actions):
            raise MirrorError("immutable target asset conflict found during planning")
        if args.dry_run:
            print("dry-run: no Gitea release or attachment was changed")
            return 0

        target_client.require_token()
        if target_release is None:
            target_release = target_client.create_release(args.gitea_tag, version)
        release_id = int(target_release["id"])
        results: list[dict[str, Any]] = []

        if args.probe_largest_full:
            probe_spec = specs[0]
            _, target_assets = target_client.refresh_assets(args.gitea_tag)
            probe_result = sync_asset(
                spec=probe_spec,
                source=source_client.require(probe_spec),
                mutable=False,
                verify_existing_sha=True,
                client=target_client,
                release_id=release_id,
                tag=args.gitea_tag,
                existing_assets=target_assets,
                temp_root=temp_root,
            )
            results.append({"name": probe_spec.name, "result": probe_result})
            _, final_assets = target_client.refresh_assets(args.gitea_tag)
            final_probe = final_assets.get(probe_spec.name)
            if final_probe is None or final_probe.size != probe_spec.size:
                raise MirrorError("large-upload probe asset is absent or has wrong size")
            verify_public_target(final_probe, probe_spec, temp_root)
            receipt = {
                "completedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "operation": operation,
                "version": version,
                "contentHash": content_hash,
                "target": (
                    f"{args.gitea_url}/{args.gitea_repo}/releases/tag/"
                    f"{args.gitea_tag}"
                ),
                "assetCount": 1,
                "totalBytes": probe_spec.size,
                "manifestChanged": False,
                "results": results,
            }
            write_json(args.receipt_out, receipt)
            print(
                f"large-upload probe complete: {probe_spec.name}, "
                f"size={probe_spec.size}, sha256={probe_spec.sha256}; "
                "manifest-dev.json unchanged"
            )
            return 0

        # Manifest is excluded from this loop by construction and synchronized
        # only after every package and the launcher succeeds.
        for spec in specs[:-1]:
            _, target_assets = target_client.refresh_assets(args.gitea_tag)
            source = source_client.require(spec)
            result = sync_asset(
                spec=spec,
                source=source,
                mutable=spec.kind == "launcher",
                verify_existing_sha=args.verify_existing_sha,
                client=target_client,
                release_id=release_id,
                tag=args.gitea_tag,
                existing_assets=target_assets,
                temp_root=temp_root,
            )
            results.append({"name": spec.name, "result": result})

        _, target_assets = target_client.refresh_assets(args.gitea_tag)
        for spec in specs[:-1]:
            target = target_assets.get(spec.name)
            if target is None or target.size != spec.size:
                raise MirrorError(
                    f"pre-manifest gate failed: {spec.name} is absent or has wrong size"
                )

        _, target_assets = target_client.refresh_assets(args.gitea_tag)
        manifest_result = sync_asset(
            spec=manifest_spec,
            source=manifest_source,
            mutable=True,
            verify_existing_sha=True,
            client=target_client,
            release_id=release_id,
            tag=args.gitea_tag,
            existing_assets=target_assets,
            temp_root=temp_root,
        )
        results.append({"name": manifest_spec.name, "result": manifest_result})

        _, final_assets = target_client.refresh_assets(args.gitea_tag)
        canonical_manifest = final_assets.get(manifest_name)
        if canonical_manifest is None:
            raise MirrorError("post-switch gate failed: canonical manifest is absent")
        verify_public_target(canonical_manifest, manifest_spec, temp_root)

        receipt = {
            "completedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": version,
            "contentHash": content_hash,
            "manifestSha256": manifest_digest,
            "target": f"{args.gitea_url}/{args.gitea_repo}/releases/tag/{args.gitea_tag}",
            "assetCount": len(specs),
            "totalBytes": total_size,
            "results": results,
        }
        write_json(args.receipt_out, receipt)
        print(
            f"mirror complete: {version}, contentHash={content_hash}, "
            f"manifestSha256={manifest_digest}"
        )
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MirrorError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
