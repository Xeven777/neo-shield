"""GitHub App access for repository snapshots.

Only read-only endpoints are used. Installation tokens are minted on demand and
kept in memory; they are never logged or persisted.
"""

from __future__ import annotations

import logging
import shutil
import tarfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx
import jwt

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"
REQUEST_TIMEOUT = 30.0
MAX_TARBALL_MEMBERS = 20_000


class GithubError(RuntimeError):
    """A GitHub request failed. Messages never contain credentials."""


def create_app_jwt(app_id: str, private_key: str) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def _api_get(
    client: httpx.AsyncClient,
    path: str,
    token: str,
    *,
    follow_redirects: bool = False,
) -> httpx.Response:
    response = await client.get(
        f"{GITHUB_API}{path}",
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {token}",
            "x-github-api-version": API_VERSION,
            "user-agent": "neoshield-worker",
        },
        follow_redirects=follow_redirects,
    )
    if response.status_code >= 400:
        raise GithubError(f"GitHub request {path} failed ({response.status_code})")
    return response


async def installation_token(
    client: httpx.AsyncClient,
    app_id: str,
    private_key: str,
    installation_id: str,
) -> str:
    jwt_token = create_app_jwt(app_id, private_key)
    response = await client.post(
        f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {jwt_token}",
            "x-github-api-version": API_VERSION,
            "user-agent": "neoshield-worker",
        },
        json={},
    )
    if response.status_code >= 400:
        raise GithubError(
            f"could not mint an installation token ({response.status_code})"
        )

    token = response.json().get("token")
    if not isinstance(token, str) or not token:
        raise GithubError("installation token response was malformed")
    return token


async def resolve_commit(
    client: httpx.AsyncClient, full_name: str, ref: str, token: str
) -> str:
    response = await _api_get(
        client, f"/repos/{full_name}/commits/{quote(ref, safe='')}", token
    )
    sha = response.json().get("sha")
    if not isinstance(sha, str) or len(sha) < 7:
        raise GithubError("could not resolve the repository commit")
    return sha


async def download_tarball(
    client: httpx.AsyncClient,
    full_name: str,
    commit: str,
    token: str,
    destination: Path,
    *,
    max_bytes: int,
) -> int:
    written = 0
    async with client.stream(
        "GET",
        f"{GITHUB_API}/repos/{full_name}/tarball/{commit}",
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {token}",
            "x-github-api-version": API_VERSION,
            "user-agent": "neoshield-worker",
        },
        follow_redirects=True,
    ) as response:
        if response.status_code >= 400:
            raise GithubError(
                f"repository archive download failed ({response.status_code})"
            )

        with destination.open("wb") as handle:
            async for chunk in response.aiter_bytes():
                written += len(chunk)
                if written > max_bytes:
                    raise GithubError("repository archive exceeds the size limit")
                handle.write(chunk)

    return written


def safe_extract(
    archive: Path,
    destination: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> int:
    """Extract regular files only, stripping the GitHub tarball root directory.

    Symlinks, hardlinks, devices and traversal paths are skipped. Size and file
    counts are bounded so a hostile repository cannot fill the disk.
    """
    destination.mkdir(parents=True, exist_ok=True)
    extracted = 0
    total_bytes = 0
    skipped: list[str] = []

    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if len(skipped) > 50:
                break
            if not member.isfile():
                skipped.append(member.name[:200])
                continue

            parts = PurePosixPath(member.name).parts
            if len(parts) < 2:
                continue

            relative = Path(*parts[1:])
            if relative.is_absolute() or ".." in relative.parts:
                skipped.append(member.name[:200])
                continue

            if member.size > max_file_bytes:
                skipped.append(member.name[:200])
                continue

            if extracted >= max_files or total_bytes + member.size > max_total_bytes:
                raise GithubError("repository archive exceeds extraction limits")

            source = tar.extractfile(member)
            if source is None:
                continue

            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as handle:
                shutil.copyfileobj(source, handle, length=1024 * 1024)

            extracted += 1
            total_bytes += member.size

    if skipped:
        logger.info("skipped %d non-regular archive entries", len(skipped))
    return extracted
