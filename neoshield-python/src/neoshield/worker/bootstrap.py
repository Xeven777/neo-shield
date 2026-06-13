"""Pinned scanner provisioning.

Binaries are downloaded from official GitHub releases on startup, verified
against the published checksum file when one exists, and stored in a writable
directory. Versions are pinned so scanner output does not drift silently.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import platform
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx

from neoshield.config import Settings
from neoshield.worker.scanners import ScannerBinaries

logger = logging.getLogger(__name__)

DOWNLOAD_TIMEOUT = 120.0
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024

GITLEAKS_VERSION = "8.21.2"
OSV_VERSION = "1.9.2"
TRIVY_VERSION = "0.76.2"


@dataclass(frozen=True, slots=True)
class Release:
    name: str
    binary: str
    version: str
    url: str
    checksum_url: str | None
    kind: Literal["tar.gz", "binary"]
    member: str | None = None

    def version_arguments(self) -> list[str]:
        return ["version"] if self.name == "gitleaks" else ["--version"]


def _architecture() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "x64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    raise RuntimeError(f"unsupported architecture: {machine}")


def releases(for_architecture: str | None = None) -> list[Release]:
    arch = for_architecture or _architecture()
    gitleaks_arch = "linux_x64" if arch == "x64" else "linux_arm64"
    osv_arch = "linux_amd64" if arch == "x64" else "linux_arm64"
    trivy_arch = "Linux-64bit" if arch == "x64" else "Linux-ARM64"

    gitleaks_asset = f"gitleaks_{GITLEAKS_VERSION}_{gitleaks_arch}.tar.gz"
    trivy_asset = f"trivy_{TRIVY_VERSION}_{trivy_arch}.tar.gz"

    return [
        Release(
            name="gitleaks",
            binary="gitleaks",
            version=GITLEAKS_VERSION,
            url=(
                "https://github.com/gitleaks/gitleaks/releases/download/"
                f"v{GITLEAKS_VERSION}/{gitleaks_asset}"
            ),
            checksum_url=(
                "https://github.com/gitleaks/gitleaks/releases/download/"
                f"v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_checksums.txt"
            ),
            kind="tar.gz",
            member="gitleaks",
        ),
        Release(
            name="osv-scanner",
            binary="osv-scanner",
            version=OSV_VERSION,
            url=(
                "https://github.com/google/osv-scanner/releases/download/"
                f"v{OSV_VERSION}/osv-scanner_{osv_arch}"
            ),
            # OSV-Scanner does not publish a checksums file for this release.
            checksum_url=None,
            kind="binary",
        ),
        Release(
            name="trivy",
            binary="trivy",
            version=TRIVY_VERSION,
            url=(
                "https://github.com/aquasecurity/trivy/releases/download/"
                f"v{TRIVY_VERSION}/{trivy_asset}"
            ),
            checksum_url=(
                "https://github.com/aquasecurity/trivy/releases/download/"
                f"v{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_checksums.txt"
            ),
            kind="tar.gz",
            member="trivy",
        ),
    ]


async def _download(client: httpx.AsyncClient, url: str) -> bytes:
    async with client.stream("GET", url, follow_redirects=True) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_DOWNLOAD_BYTES:
                raise RuntimeError("scanner download exceeded the size limit")
            chunks.append(chunk)
    return b"".join(chunks)


def _expected_checksum(checksums: str, asset_name: str) -> str | None:
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0].strip(), parts[-1].strip().lstrip("*")
        if name == asset_name:
            return digest.lower()
    return None


async def _install(
    client: httpx.AsyncClient, release: Release, scanner_dir: Path
) -> Path:
    asset_name = release.url.rsplit("/", 1)[-1]
    payload = await _download(client, release.url)

    if release.checksum_url:
        checksums = (await _download(client, release.checksum_url)).decode(
            "utf-8", "replace"
        )
        expected = _expected_checksum(checksums, asset_name)
        if expected is None:
            raise RuntimeError(
                f"no published checksum for {asset_name}; refusing to install"
            )
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise RuntimeError(f"checksum mismatch for {asset_name}")

    binary_path = scanner_dir / release.binary

    if release.kind == "binary":
        binary_path.write_bytes(payload)
    else:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            member = None
            for candidate in archive.getmembers():
                if candidate.isfile() and candidate.name.rsplit("/", 1)[-1] == (
                    release.member or release.binary
                ):
                    member = candidate
                    break
            if member is None:
                raise RuntimeError(f"{release.name} archive did not contain a binary")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"{release.name} archive was malformed")
            with source:
                binary_path.write_bytes(source.read())

    binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return binary_path


async def ensure_scanners(settings: Settings) -> ScannerBinaries:
    scanner_dir = Path(settings.scanner_dir)
    try:
        scanner_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        logger.error("scanner directory is not writable: %s", error)
        return ScannerBinaries(None, None, None)

    installed: dict[str, Path | None] = {}
    release_list = releases()

    async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT) as client:
        for release in release_list:
            binary_path = scanner_dir / release.binary
            if binary_path.is_file() and os.access(binary_path, os.X_OK):
                installed[release.name] = binary_path
                continue

            if not settings.scanner_auto_install:
                logger.warning(
                    "%s is missing and NEOSHIELD_SCANNER_AUTO_INSTALL is false",
                    release.name,
                )
                installed[release.name] = None
                continue

            logger.info(
                "installing %s %s into %s",
                release.name,
                release.version,
                scanner_dir,
            )
            try:
                installed[release.name] = await _install(
                    client, release, scanner_dir
                )
            except (httpx.HTTPError, OSError, RuntimeError, tarfile.TarError) as error:
                logger.error("could not install %s: %s", release.name, error)
                installed[release.name] = None

    return ScannerBinaries(
        gitleaks=installed.get("gitleaks"),
        osv_scanner=installed.get("osv-scanner"),
        trivy=installed.get("trivy"),
    )
