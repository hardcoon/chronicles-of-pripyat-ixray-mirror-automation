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
DEV_VERSION_RE = re.compile(r"^(?P<date>\d{4}\.\d{2}\.\d{2})-dev\.(?P<number>[1-9]\d*)$")
DEFAULT_SOURCE_REPO = "hardcoon/chronicles-of-pripyat-ixray"
DEFAULT_SOURCE_TAG = "dev-2026.08.26.1"
DEFAULT_TARGET_REPO = "hardcoon/chronicles-of-pripyat-ixray-downloads"
DEFAULT_GITEA_URL = "https://gitea.com"
DEFAULT_TARGET_TAG = "dev-channel"
DEFAULT_MANIFEST_NAME = "manifest-dev.json"
DEFAULT_LAUNCHER_NAME = "ChroniclesLauncher.exe"
ROLLBACK_GUARD_ENV = "GITEA_MIRROR_ROLLBACK_ENABLED"
MAX_PUBLISHED_MANIFEST_BYTES = 32 * 1024 * 1024
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


TargetAssets = dict[str, list[TargetAsset]]


@dataclasses.dataclass(frozen=True)
class ManifestIdentity:
    version: str
    dev_number: int
    content_hash: str
    sha256: str


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


def manifest_identity(
    manifest: Mapping[str, Any], digest: str, field: str
) -> ManifestIdentity:
    version_value = manifest.get("version")
    if not isinstance(version_value, str) or not version_value.strip():
        raise MirrorError(f"{field}.version must be a non-empty string")
    version = version_value.strip()
    match = DEV_VERSION_RE.fullmatch(version)
    if match is None:
        raise MirrorError(
            f"{field}.version must use YYYY.MM.DD-dev.N with a positive global N"
        )
    return ManifestIdentity(
        version=version,
        dev_number=int(match.group("number")),
        content_hash=normalize_sha256(
            manifest.get("contentHash"), f"{field}.contentHash"
        ),
        sha256=normalize_sha256(digest, f"{field} SHA-256"),
    )


def validate_manifest_progression(
    source: ManifestIdentity,
    published: Sequence[ManifestIdentity],
    *,
    allow_rollback: bool,
) -> str:
    """Fail closed when a source manifest could roll back the dev channel."""

    if not published:
        return "bootstrap"
    newest_number = max(item.dev_number for item in published)
    newest = [item for item in published if item.dev_number == newest_number]
    if source.dev_number > newest_number:
        return "advance"
    if source.dev_number == newest_number and all(
        item.content_hash == source.content_hash for item in newest
    ):
        return "idempotent"
    if allow_rollback:
        return "guarded-rollback"
    if source.dev_number < newest_number:
        detail = (
            f"source {source.version} has dev.{source.dev_number}, but the target "
            f"already contains dev.{newest_number}"
        )
    else:
        detail = (
            f"source {source.version} reuses dev.{source.dev_number} with a different "
            "contentHash"
        )
    raise MirrorError(
        f"refusing target manifest rollback/non-idempotent rewrite: {detail}"
    )


def rollback_override_enabled(
    requested: bool, environment: Mapping[str, str]
) -> bool:
    if not requested:
        return False
    if environment.get(ROLLBACK_GUARD_ENV) != "true":
        raise MirrorError(
            f"--allow-rollback also requires {ROLLBACK_GUARD_ENV}=true"
        )
    return True


def effective_existing_sha_verification(
    *, requested: bool, probe: bool, published_manifest_count: int
) -> bool:
    # Before a canonical manifest exists, no target package has inherited trust
    # from an earlier completed mirror.  Bootstrap therefore always hashes it.
    return requested or probe or published_manifest_count == 0


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


def validate_content_range(
    value: str | None, *, offset: int, expected_size: int | None
) -> None:
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+|\*)", value or "")
    if match is None:
        raise MirrorError("resumed download returned an invalid Content-Range")
    start, end = int(match.group(1)), int(match.group(2))
    if start != offset or end < start:
        raise MirrorError(
            f"resumed download returned Content-Range {value!r} for offset {offset}"
        )
    total_text = match.group(3)
    if expected_size is not None:
        if total_text == "*" or int(total_text) != expected_size:
            raise MirrorError(
                f"resumed download returned Content-Range {value!r}; "
                f"expected total {expected_size}"
            )
        if end >= expected_size:
            raise MirrorError(
                f"resumed download returned Content-Range {value!r} beyond the file"
            )


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
            if expected_size is not None and offset > expected_size:
                partial.unlink()
                offset = 0
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
                    if offset and status == 206:
                        validate_content_range(
                            response.headers.get("Content-Range"),
                            offset=offset,
                            expected_size=expected_size,
                        )
                        mode = "ab"
                    elif status == 200:
                        # A server may ignore Range.  Replacing the partial file
                        # with the complete 200 response is safe.
                        offset = 0
                        mode = "wb"
                    else:
                        raise MirrorError(
                            f"download returned unexpected HTTP {status} at offset {offset}"
                        )
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
        except (
            OSError,
            http.client.HTTPException,
            urllib.error.URLError,
            MirrorError,
        ) as exc:
            last_error = exc
            if isinstance(exc, MirrorError) and (
                "SHA-256 mismatch" in str(exc)
                or "Content-Range" in str(exc)
            ):
                partial.unlink(missing_ok=True)
                if "SHA-256 mismatch" in str(exc):
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

    def canonical_download_url(self, tag: str, name: str) -> str:
        encoded_tag = urllib.parse.quote(tag, safe="")
        encoded_name = urllib.parse.quote(validate_asset_name(name), safe="")
        return (
            f"{self.base_url}/{self.owner}/{self.repo}/releases/download/"
            f"{encoded_tag}/{encoded_name}"
        )

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
    def release_assets(release: Mapping[str, Any]) -> TargetAssets:
        result: TargetAssets = {}
        raw_assets = release.get("assets") or []
        if not isinstance(raw_assets, list):
            raise MirrorError("Gitea release assets field is invalid")
        for raw in raw_assets:
            if not isinstance(raw, Mapping):
                raise MirrorError("Gitea release contains an invalid asset record")
            name = validate_asset_name(raw.get("name"), "Gitea asset name")
            asset = TargetAsset(
                id=int(raw["id"]),
                name=name,
                size=int(raw["size"]),
                download_url=str(raw.get("browser_download_url") or ""),
            )
            result.setdefault(name, []).append(asset)
        for assets in result.values():
            assets.sort(key=lambda item: item.id)
        return result

    def refresh_assets(self, tag: str) -> tuple[Mapping[str, Any], TargetAssets]:
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
        if not uploaded.download_url.startswith("https://"):
            raise MirrorError(f"Gitea upload of {target_name} returned an unsafe URL")
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
        try:
            renamed = TargetAsset(
                id=int(raw["id"]),
                name=validate_asset_name(raw["name"], "renamed asset name"),
                size=int(raw["size"]),
                download_url=str(raw["browser_download_url"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MirrorError("Gitea rename response is invalid") from exc
        if renamed.id != asset_id or renamed.name != name:
            raise MirrorError(
                f"Gitea rename metadata mismatch for attachment {asset_id}: "
                f"name={renamed.name!r}"
            )
        return renamed

    def delete(self, release_id: int, asset_id: int) -> None:
        self.require_token()
        request_json(
            f"{self.api_root}/releases/{release_id}/assets/{asset_id}",
            method="DELETE",
            headers=self.auth_headers,
            expected=(204,),
        )


def target_candidates(assets: TargetAssets, name: str) -> list[TargetAsset]:
    return list(assets.get(name, ()))


def target_by_id(assets: TargetAssets, asset_id: int) -> TargetAsset | None:
    for candidates in assets.values():
        for candidate in candidates:
            if candidate.id == asset_id:
                return candidate
    return None


def target_with_prefix(assets: TargetAssets, prefix: str) -> list[TargetAsset]:
    result: list[TargetAsset] = []
    for name, candidates in assets.items():
        if name.startswith(prefix):
            result.extend(candidates)
    return sorted(result, key=lambda item: item.id)


def refresh_after_ambiguous_write(
    client: GiteaReleaseClient,
    tag: str,
    *,
    attempts: int = 3,
) -> TargetAssets:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            _, assets = client.refresh_assets(tag)
            return assets
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(min(2**attempt, 4))
    raise MirrorError(
        f"could not reconcile an ambiguous Gitea write: {last_error}"
    ) from last_error


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


def verify_public_canonical(
    client: GiteaReleaseClient,
    tag: str,
    spec: AssetSpec,
    temp_root: Path,
) -> None:
    destination = temp_root / f"verify-canonical-{spec.name}"
    try:
        download_file(
            client.canonical_download_url(tag, spec.name),
            destination,
            expected_size=spec.size,
            expected_sha256=spec.sha256,
        )
    finally:
        destination.unlink(missing_ok=True)


def published_manifest_candidates(
    assets: TargetAssets, manifest_name: str
) -> list[TargetAsset]:
    canonical = target_candidates(assets, manifest_name)
    if canonical:
        return canonical
    # The superseded old->previous swap could crash after removing the
    # canonical name.  That previous ID is still the published checkpoint and
    # must participate in rollback checks before sync restores its name.
    previous = target_with_prefix(assets, f"{manifest_name}.previous-")
    if len(previous) > 1:
        raise MirrorError(
            "cannot identify the published manifest: multiple previous IDs exist"
        )
    return previous


def load_published_manifest_identities(
    assets: TargetAssets, manifest_name: str, temp_root: Path
) -> list[ManifestIdentity]:
    candidates = published_manifest_candidates(assets, manifest_name)
    if len(candidates) > 8:
        raise MirrorError("target contains too many canonical manifest attachments")
    result: list[ManifestIdentity] = []
    for asset in candidates:
        if not asset.download_url.startswith("https://"):
            raise MirrorError(
                f"published manifest attachment {asset.id} has no public HTTPS URL"
            )
        if asset.size <= 0 or asset.size > MAX_PUBLISHED_MANIFEST_BYTES:
            raise MirrorError(
                f"published manifest attachment {asset.id} has unsafe size {asset.size}"
            )
        destination = temp_root / f"published-manifest-{asset.id}.json"
        try:
            _, digest = download_file(
                asset.download_url,
                destination,
                expected_size=asset.size,
                expected_sha256=None,
            )
            try:
                raw = json.loads(destination.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as exc:
                raise MirrorError(
                    f"published manifest attachment {asset.id} is not valid UTF-8 JSON"
                ) from exc
            if not isinstance(raw, Mapping):
                raise MirrorError(
                    f"published manifest attachment {asset.id} root is not an object"
                )
            result.append(
                manifest_identity(raw, digest, f"published manifest {asset.id}")
            )
        finally:
            destination.unlink(missing_ok=True)
    return result


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


def upload_with_reconciliation(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    source_path: Path,
    target_name: str,
    spec: AssetSpec,
    temp_root: Path,
) -> TargetAsset:
    try:
        return client.upload(release_id, source_path, target_name)
    except Exception as upload_error:
        verified: list[TargetAsset] = []
        for attempt in range(3):
            try:
                _, assets = client.refresh_assets(tag)
            except Exception:
                assets = {}
            verified = []
            for candidate in target_candidates(assets, target_name):
                if candidate.size != spec.size:
                    continue
                try:
                    verify_public_target(candidate, spec, temp_root)
                except MirrorError:
                    continue
                verified.append(candidate)
            if len(verified) == 1:
                print(
                    f"reconciled upload after ambiguous response: {target_name}",
                    file=sys.stderr,
                )
                return verified[0]
            if len(verified) > 1:
                break
            if attempt < 2:
                time.sleep(min(2**attempt, 4))
        raise MirrorError(
            f"Gitea upload status for {target_name} is ambiguous after error: "
            f"{upload_error}; found {len(verified)} verified candidates"
        ) from upload_error


def rename_with_reconciliation(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    asset: TargetAsset,
    name: str,
) -> TargetAsset:
    try:
        return client.rename(release_id, asset.id, name)
    except Exception as rename_error:
        current: TargetAsset | None = None
        for attempt in range(3):
            try:
                _, assets = client.refresh_assets(tag)
            except Exception:
                assets = {}
            current = target_by_id(assets, asset.id)
            if (
                current is not None
                and current.name == name
                and current.size == asset.size
            ):
                print(
                    f"reconciled rename after ambiguous response: {asset.id} -> {name}",
                    file=sys.stderr,
                )
                return current
            if attempt < 2:
                time.sleep(min(2**attempt, 4))
        state = "absent" if current is None else f"still named {current.name!r}"
        raise MirrorError(
            f"Gitea rename of attachment {asset.id} to {name!r} failed; "
            f"server state is {state}: {rename_error}"
        ) from rename_error


def delete_with_reconciliation(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    asset: TargetAsset,
) -> None:
    try:
        client.delete(release_id, asset.id)
        return
    except Exception as delete_error:
        for attempt in range(3):
            try:
                _, assets = client.refresh_assets(tag)
            except Exception:
                assets = {asset.name: [asset]}
            if target_by_id(assets, asset.id) is None:
                print(
                    f"reconciled delete after ambiguous response: {asset.id}",
                    file=sys.stderr,
                )
                return
            if attempt < 2:
                time.sleep(min(2**attempt, 4))
        raise MirrorError(
            f"Gitea deletion of attachment {asset.id} did not complete: {delete_error}"
        ) from delete_error


def reconcile_legacy_previous(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    spec: AssetSpec,
    assets: TargetAssets,
) -> TargetAssets:
    """Recover a canonical name left absent by the superseded swap protocol."""

    if target_candidates(assets, spec.name):
        return assets
    previous = target_with_prefix(assets, f"{spec.name}.previous-")
    if not previous:
        return assets
    if len(previous) != 1:
        raise MirrorError(
            f"cannot safely recover absent {spec.name}: multiple previous IDs exist"
        )
    rename_with_reconciliation(
        client=client,
        release_id=release_id,
        tag=tag,
        asset=previous[0],
        name=spec.name,
    )
    _, refreshed = client.refresh_assets(tag)
    if not target_candidates(refreshed, spec.name):
        raise MirrorError(f"failed to restore absent canonical {spec.name}")
    return refreshed


def verified_pending_asset(
    assets: TargetAssets, spec: AssetSpec, temp_root: Path
) -> TargetAsset | None:
    prefix = f"{spec.name}.pending-{spec.sha256[:12]}-"
    verified: list[TargetAsset] = []
    for candidate in target_with_prefix(assets, prefix):
        if candidate.size != spec.size:
            continue
        try:
            verify_public_target(candidate, spec, temp_root)
        except MirrorError:
            continue
        verified.append(candidate)
    return max(verified, key=lambda item: item.id) if verified else None


def replace_mutable_attachment(
    *,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    existing: Sequence[TargetAsset],
    source_path: Path | None,
    spec: AssetSpec,
    temp_root: Path,
    staged: TargetAsset | None = None,
) -> None:
    """Publish a mutable asset without ever removing the prior canonical name.

    Gitea permits duplicate attachment names.  The new bytes are therefore
    staged and anonymously verified first, renamed to the canonical name while
    every old canonical attachment still exists, and only then are the old IDs
    deleted.  A timeout after a successful mutation is reconciled by ID.
    """

    suffix = f"{spec.sha256[:12]}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    pending_name = validate_asset_name(f"{spec.name}.pending-{suffix}")
    if staged is None:
        if source_path is None:
            raise MirrorError(f"no source file is available for {spec.name}")
        pending = upload_with_reconciliation(
            client=client,
            release_id=release_id,
            tag=tag,
            source_path=source_path,
            target_name=pending_name,
            spec=spec,
            temp_root=temp_root,
        )
    else:
        pending = staged
        pending_name = staged.name
        print(f"reusing verified staged attachment: {pending.name}")
    try:
        verify_public_target(pending, spec, temp_root)
    except Exception:
        try:
            delete_with_reconciliation(
                client=client,
                release_id=release_id,
                tag=tag,
                asset=pending,
            )
        except Exception as cleanup_error:
            print(
                f"WARNING: failed staged upload {pending.id} could not be removed: "
                f"{cleanup_error}",
                file=sys.stderr,
            )
        raise

    try:
        canonical_new = rename_with_reconciliation(
            client=client,
            release_id=release_id,
            tag=tag,
            asset=pending,
            name=spec.name,
        )
    except Exception:
        # A timed-out PATCH remains ambiguous even after a few stale reads.
        # Never delete this ID here: the server may have committed the rename.
        # A rerun classifies it by ID/name/SHA and safely resumes either state.
        print(
            f"WARNING: leaving attachment {pending.id} for rerun reconciliation "
            "after an ambiguous rename",
            file=sys.stderr,
        )
        raise

    # The same UUID-backed bytes were already verified while staged.  Recheck
    # them after the rename before retiring any previous canonical ID.
    verify_public_target(canonical_new, spec, temp_root)
    for previous in existing:
        if previous.id == canonical_new.id:
            continue
        delete_with_reconciliation(
            client=client,
            release_id=release_id,
            tag=tag,
            asset=previous,
        )

    assets = refresh_after_ambiguous_write(client, tag)
    for stale in (
        target_with_prefix(assets, f"{spec.name}.previous-")
        + target_with_prefix(
            assets, f"{spec.name}.pending-{spec.sha256[:12]}-"
        )
    ):
        delete_with_reconciliation(
            client=client,
            release_id=release_id,
            tag=tag,
            asset=stale,
        )
    assets = refresh_after_ambiguous_write(client, tag)
    final = target_by_id(assets, canonical_new.id)
    if final is None or final.name != spec.name or final.size != spec.size:
        raise MirrorError(
            f"post-switch gate failed for {spec.name}: new canonical ID is missing"
        )
    leftovers = [
        item for item in target_candidates(assets, spec.name) if item.id != final.id
    ]
    if leftovers:
        raise MirrorError(
            f"post-switch gate failed for {spec.name}: duplicate canonical IDs remain"
        )
    verify_public_target(final, spec, temp_root)
    verify_public_canonical(client, tag, spec, temp_root)


def sync_asset(
    *,
    spec: AssetSpec,
    source: SourceAsset,
    mutable: bool,
    verify_existing_sha: bool,
    client: GiteaReleaseClient,
    release_id: int,
    tag: str,
    existing_assets: TargetAssets,
    temp_root: Path,
) -> str:
    if mutable:
        existing_assets = reconcile_legacy_previous(
            client=client,
            release_id=release_id,
            tag=tag,
            spec=spec,
            assets=existing_assets,
        )
    candidates = target_candidates(existing_assets, spec.name)
    if not mutable and len(candidates) > 1:
        raise MirrorError(f"immutable Gitea asset {spec.name} has duplicate attachments")

    if mutable:
        verified: list[TargetAsset] = []
        for candidate in candidates:
            if candidate.size != spec.size:
                continue
            try:
                verify_public_target(candidate, spec, temp_root)
            except MirrorError:
                continue
            verified.append(candidate)
        if verified:
            keeper = max(verified, key=lambda item: item.id)
            extras = [item for item in candidates if item.id != keeper.id]
            for extra in extras:
                delete_with_reconciliation(
                    client=client,
                    release_id=release_id,
                    tag=tag,
                    asset=extra,
                )
            _, refreshed = client.refresh_assets(tag)
            current = target_by_id(refreshed, keeper.id)
            canonical = target_candidates(refreshed, spec.name)
            if (
                current is None
                or current.name != spec.name
                or len(canonical) != 1
            ):
                raise MirrorError(
                    f"reconciliation lost canonical attachment {spec.name}"
                )
            verify_public_target(current, spec, temp_root)
            verify_public_canonical(client, tag, spec, temp_root)
            for stale in target_with_prefix(
                refreshed, f"{spec.name}.previous-"
            ) + target_with_prefix(
                refreshed, f"{spec.name}.pending-{spec.sha256[:12]}-"
            ):
                delete_with_reconciliation(
                    client=client,
                    release_id=release_id,
                    tag=tag,
                    asset=stale,
                )
            print(f"verified existing: {spec.name}")
            return "reconciled-existing" if extras else "verified-existing"

    existing = candidates[0] if candidates else None
    if not mutable and existing is not None and existing.size == spec.size:
        if verify_existing_sha:
            verify_public_target(existing, spec, temp_root)
            print(f"verified existing: {spec.name}")
            return "verified-existing"
        else:
            # Immutable package filenames are content/version specific.  A first
            # bootstrap should use --verify-existing-sha; later jobs may trust
            # the size of assets that a previous successful job verified.
            print(f"reused immutable asset by name/size: {spec.name}")
            return "reused-existing"
    elif not mutable and existing is not None:
        raise MirrorError(
            f"immutable Gitea asset {spec.name} has size {existing.size}; "
            f"expected {spec.size}. Refusing destructive replacement."
        )

    staged = (
        verified_pending_asset(existing_assets, spec, temp_root)
        if mutable
        else None
    )
    source_path = None if staged is not None else download_source(source, spec, temp_root)
    try:
        if mutable:
            replace_mutable_attachment(
                client=client,
                release_id=release_id,
                tag=tag,
                existing=candidates,
                source_path=source_path,
                spec=spec,
                temp_root=temp_root,
                staged=staged,
            )
            outcome = "replaced" if candidates else "uploaded"
            print(f"{outcome} and verified: {spec.name}")
            return outcome

        assert source_path is not None
        uploaded: TargetAsset | None = None
        try:
            uploaded = upload_with_reconciliation(
                client=client,
                release_id=release_id,
                tag=tag,
                source_path=source_path,
                target_name=spec.name,
                spec=spec,
                temp_root=temp_root,
            )
            verify_public_target(uploaded, spec, temp_root)
        except Exception:
            if uploaded is not None:
                try:
                    delete_with_reconciliation(
                        client=client,
                        release_id=release_id,
                        tag=tag,
                        asset=uploaded,
                    )
                except Exception:
                    pass
            raise
        print(f"uploaded and verified: {spec.name}")
        return "uploaded"
    finally:
        if source_path is not None:
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
        "--allow-rollback",
        action="store_true",
        help=(
            "Emergency-only override for source-tag/version rollback guards. "
            f"Also requires {ROLLBACK_GUARD_ENV}=true; never passed by the workflow."
        ),
    )
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
        help=(
            "Download/hash every existing immutable Gitea package. Bootstrap "
            "enables this automatically."
        ),
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
    allow_rollback = rollback_override_enabled(args.allow_rollback, os.environ)
    if (
        not args.dry_run
        and args.github_tag != DEFAULT_SOURCE_TAG
        and not allow_rollback
    ):
        raise MirrorError(
            f"write operations require the persistent source tag {DEFAULT_SOURCE_TAG!r}; "
            "a different tag requires the guarded emergency rollback override"
        )
    github_token = os.environ.get(args.github_token_env) or None
    # A plan cannot write and must not even receive a credential in-process.
    gitea_token = (
        None if args.dry_run else (os.environ.get(args.gitea_token_env) or None)
    )

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
        source_identity = manifest_identity(manifest, manifest_digest, "manifest")
        version = source_identity.version
        content_hash = source_identity.content_hash

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
        published_identities = load_published_manifest_identities(
            target_assets, manifest_name, temp_root
        )
        progression = validate_manifest_progression(
            source_identity,
            published_identities,
            allow_rollback=allow_rollback,
        )
        bootstrap_sha_verification = not published_identities
        verify_existing_sha = effective_existing_sha_verification(
            requested=args.verify_existing_sha,
            probe=args.probe_largest_full,
            published_manifest_count=len(published_identities),
        )

        actions: list[dict[str, Any]] = []
        for spec in specs:
            current = target_candidates(target_assets, spec.name)
            mutable = spec.kind in {"launcher", "manifest-last"}
            if not current:
                action = "stage-verify-publish" if mutable else "upload"
            elif mutable:
                action = "verify-or-reconcile"
            elif len(current) > 1 or current[0].size != spec.size:
                action = "conflict"
            elif verify_existing_sha:
                action = "verify"
            else:
                action = "reuse-by-name-size"
            actions.append(
                {
                    "name": spec.name,
                    "kind": spec.kind,
                    "size": spec.size,
                    "sha256": spec.sha256,
                    "action": action,
                    "targetCanonicalCount": len(current),
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
                "publishedVersions": [
                    item.version for item in published_identities
                ],
            },
            "version": version,
            "contentHash": content_hash,
            "manifestProgression": progression,
            "rollbackOverride": allow_rollback,
            "bootstrapRequiresExistingSha": bootstrap_sha_verification,
            "effectiveVerifyExistingSha": verify_existing_sha,
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
            final_probe_candidates = target_candidates(final_assets, probe_spec.name)
            if (
                len(final_probe_candidates) != 1
                or final_probe_candidates[0].size != probe_spec.size
            ):
                raise MirrorError("large-upload probe asset is absent or has wrong size")
            final_probe = final_probe_candidates[0]
            verify_public_target(final_probe, probe_spec, temp_root)
            receipt = {
                "completedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "operation": operation,
                "version": version,
                "contentHash": content_hash,
                "manifestProgression": progression,
                "rollbackOverride": allow_rollback,
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
            if spec.kind == "launcher":
                latest_published = load_published_manifest_identities(
                    target_assets, manifest_name, temp_root
                )
                progression = validate_manifest_progression(
                    source_identity,
                    latest_published,
                    allow_rollback=allow_rollback,
                )
            source = source_client.require(spec)
            result = sync_asset(
                spec=spec,
                source=source,
                mutable=spec.kind == "launcher",
                verify_existing_sha=verify_existing_sha,
                client=target_client,
                release_id=release_id,
                tag=args.gitea_tag,
                existing_assets=target_assets,
                temp_root=temp_root,
            )
            results.append({"name": spec.name, "result": result})

        _, target_assets = target_client.refresh_assets(args.gitea_tag)
        for spec in specs[:-1]:
            target = target_candidates(target_assets, spec.name)
            if len(target) != 1 or target[0].size != spec.size:
                raise MirrorError(
                    f"pre-manifest gate failed: {spec.name} is absent or has wrong size"
                )

        _, target_assets = target_client.refresh_assets(args.gitea_tag)
        latest_published = load_published_manifest_identities(
            target_assets, manifest_name, temp_root
        )
        progression = validate_manifest_progression(
            source_identity,
            latest_published,
            allow_rollback=allow_rollback,
        )
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
        canonical_manifests = target_candidates(final_assets, manifest_name)
        if len(canonical_manifests) != 1:
            raise MirrorError(
                "post-switch gate failed: canonical manifest is absent or duplicated"
            )
        canonical_manifest = canonical_manifests[0]
        verify_public_target(canonical_manifest, manifest_spec, temp_root)
        verify_public_canonical(
            target_client, args.gitea_tag, manifest_spec, temp_root
        )

        receipt = {
            "completedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": version,
            "contentHash": content_hash,
            "manifestSha256": manifest_digest,
            "manifestProgression": progression,
            "rollbackOverride": allow_rollback,
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
