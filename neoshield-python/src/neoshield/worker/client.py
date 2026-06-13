from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class WorkerAuthError(RuntimeError):
    """The web app rejected the worker credential."""


class WorkerRequestError(RuntimeError):
    """The web app returned an unexpected response."""


@dataclass(frozen=True)
class Heartbeat:
    worker_id: str
    workspace_id: str
    name: str
    scopes: tuple[str, ...]
    interval_seconds: int


def _parse_heartbeat(payload: dict[str, Any]) -> Heartbeat:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise WorkerRequestError("heartbeat response is missing data")

    try:
        return Heartbeat(
            worker_id=str(data["workerId"]),
            workspace_id=str(data["workspaceId"]),
            name=str(data["name"]),
            scopes=tuple(str(scope) for scope in data.get("scopes", [])),
            interval_seconds=int(data.get("heartbeatIntervalSeconds", 30)),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise WorkerRequestError("heartbeat response is malformed") from error


class WorkerClient:
    """Talks to the Next.js internal worker API.

    Authentication is a workspace-scoped, revocable bearer token. The token is
    never included in logs or error messages.
    """

    def __init__(
        self,
        web_url: str,
        token: str | None,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._web_url = web_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._transport = transport

    @property
    def has_token(self) -> bool:
        return bool(self._token)

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise WorkerAuthError("no worker token configured")
        return {
            "authorization": f"Bearer {self._token}",
            "accept": "application/json",
        }

    async def heartbeat(self, *, version: str, hostname: str) -> Heartbeat:
        payload = {"version": version[:40], "hostname": hostname[:200]}
        async with httpx.AsyncClient(
            timeout=self._timeout, transport=self._transport
        ) as client:
            response = await client.post(
                f"{self._web_url}/api/internal/worker/heartbeat",
                json=payload,
                headers=self._headers(),
            )

        if response.status_code in (401, 403):
            raise WorkerAuthError("worker token was rejected or revoked")
        if response.status_code >= 400:
            raise WorkerRequestError(
                f"heartbeat failed with status {response.status_code}"
            )

        return _parse_heartbeat(response.json())

    async def register(
        self,
        *,
        bootstrap_token: str,
        workspace_id: str,
        name: str,
        version: str,
        hostname: str,
    ) -> str:
        """First-boot registration. Returns the new worker token (not cached)."""
        payload = {
            "workspaceId": workspace_id,
            "name": name[:80],
            "version": version[:40],
            "hostname": hostname[:200],
        }
        async with httpx.AsyncClient(
            timeout=self._timeout, transport=self._transport
        ) as client:
            response = await client.post(
                f"{self._web_url}/api/internal/workers/register",
                json=payload,
                headers={
                    "authorization": f"Bearer {bootstrap_token}",
                    "accept": "application/json",
                },
            )

        if response.status_code in (401, 403):
            raise WorkerAuthError("worker bootstrap token was rejected")
        if response.status_code >= 400:
            raise WorkerRequestError(
                f"registration failed with status {response.status_code}"
            )

        data = response.json().get("data", {})
        token = data.get("token")
        if not isinstance(token, str) or not token:
            raise WorkerRequestError("registration response is missing a token")
        return token
