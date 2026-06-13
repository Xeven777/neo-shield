"""Small read-only client for the Wazuh indexer and manager APIs.

Alerts live in the Wazuh indexer (an OpenSearch distribution); the manager API
adds agent inventory. Both listen on private interfaces. Credentials are read
from the worker environment and are never written to the database or logs.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from neoshield.config import Settings

logger = logging.getLogger(__name__)

MANAGER_TOKEN_TTL = timedelta(minutes=10)


class WazuhError(RuntimeError):
    """A Wazuh request failed. Messages never include credentials."""


class WazuhAuthError(WazuhError):
    """Wazuh rejected the configured credentials."""


def _verify(verify_tls: bool, ca_path: str | None) -> bool | str:
    if not verify_tls:
        return False
    return ca_path or True


class WazuhClient:
    def __init__(
        self,
        settings: Settings,
        *,
        index_transport: httpx.AsyncBaseTransport | None = None,
        manager_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._indexer = httpx.AsyncClient(
            timeout=settings.wazuh_request_timeout_seconds,
            verify=_verify(
                settings.wazuh_indexer_verify_tls,
                settings.wazuh_indexer_ca_path,
            ),
            follow_redirects=False,
            transport=index_transport,
        )
        self._manager = httpx.AsyncClient(
            timeout=settings.wazuh_request_timeout_seconds,
            verify=_verify(
                settings.wazuh_manager_verify_tls,
                settings.wazuh_indexer_ca_path,
            ),
            follow_redirects=False,
            transport=manager_transport,
        )
        self._manager_token: str | None = None
        self._manager_token_expires: datetime | None = None

    # ------------------------------------------------------------------ indexer

    @property
    def configured(self) -> bool:
        return self._settings.wazuh_configured

    @property
    def manager_configured(self) -> bool:
        return self._settings.wazuh_manager_configured

    def _indexer_headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self._settings.wazuh_indexer_api_token:
            headers["authorization"] = (
                f"Bearer {self._settings.wazuh_indexer_api_token}"
            )
        return headers

    def _indexer_auth(self) -> httpx.BasicAuth | None:
        if self._settings.wazuh_indexer_api_token:
            return None
        username = self._settings.wazuh_indexer_username or ""
        password = self._settings.wazuh_indexer_password or ""
        return httpx.BasicAuth(username, password)

    async def search_alerts(
        self,
        *,
        after: datetime,
        min_level: int,
        size: int,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return alert hits newer than `after` (ascending by timestamp)."""
        if not self.configured:
            raise WazuhError("Wazuh indexer is not configured on this worker")

        filters: list[dict[str, Any]] = [
            {"range": {"timestamp": {"gte": after.astimezone(UTC).isoformat()}}},
            {"range": {"rule.level": {"gte": max(0, min_level)}}},
        ]
        if agent_id:
            filters.append({"term": {"agent.id": agent_id}})
        else:
            # Agent 000 is the manager itself and is intentionally not an
            # endpoint. Exclude it at query time so manager-only alerts cannot
            # consume the bounded batch and starve real agent alerts.
            filters.append(
                {"bool": {"must_not": [{"term": {"agent.id": "000"}}]}}
            )

        body = {
            "size": max(1, min(size, 1000)),
            "sort": [{"timestamp": {"order": "asc"}}],
            "track_total_hits": False,
            "query": {"bool": {"filter": filters}},
        }

        url = (
            f"{self._settings.wazuh_indexer_url.rstrip('/')}/"
            f"{self._settings.wazuh_index_pattern}/_search"
        )
        try:
            response = await self._indexer.post(
                url,
                json=body,
                headers=self._indexer_headers(),
                auth=self._indexer_auth(),
            )
        except httpx.HTTPError as error:
            raise WazuhError(f"indexer request failed: {error}") from error

        if response.status_code in (401, 403):
            raise WazuhAuthError("indexer rejected the configured credentials")
        if response.status_code == 404:
            # The alert index does not exist until the first alert is written.
            return []
        if response.status_code >= 400:
            raise WazuhError(
                f"indexer returned HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as error:
            raise WazuhError("indexer returned a non-JSON response") from error

        hits = payload.get("hits", {}).get("hits", [])
        if not isinstance(hits, list):
            raise WazuhError("indexer response is missing hits")

        return [hit for hit in hits if isinstance(hit, dict)]

    # ------------------------------------------------------------------ manager

    async def _manager_token_value(self) -> str:
        now = datetime.now(UTC)
        if (
            self._manager_token
            and self._manager_token_expires
            and now < self._manager_token_expires
        ):
            return self._manager_token

        if not self.manager_configured:
            raise WazuhError("Wazuh manager API is not configured on this worker")

        url = (
            f"{self._settings.wazuh_manager_url.rstrip('/')}"
            "/security/user/authenticate"
        )
        try:
            response = await self._manager.post(
                url,
                auth=httpx.BasicAuth(
                    self._settings.wazuh_manager_username or "",
                    self._settings.wazuh_manager_password or "",
                ),
            )
        except httpx.HTTPError as error:
            raise WazuhError(f"manager authentication failed: {error}") from error

        if response.status_code in (401, 403):
            raise WazuhAuthError("manager rejected the configured credentials")
        if response.status_code >= 400:
            raise WazuhError(
                f"manager authentication returned HTTP {response.status_code}"
            )

        try:
            token = response.json().get("data", {}).get("token")
        except ValueError as error:
            raise WazuhError("manager returned a non-JSON response") from error

        if not isinstance(token, str) or not token:
            raise WazuhError("manager authentication did not return a token")

        self._manager_token = token
        self._manager_token_expires = now + MANAGER_TOKEN_TTL
        return token

    async def list_agents(self) -> list[dict[str, Any]]:
        """Return agent inventory. Paginates to a bounded 2,000 agents."""
        if not self.manager_configured:
            return []

        token = await self._manager_token_value()
        agents: list[dict[str, Any]] = []
        offset = 0
        limit = 500
        url = f"{self._settings.wazuh_manager_url.rstrip('/')}/agents"

        while offset < 2000:
            try:
                response = await self._manager.get(
                    url,
                    params={
                        "limit": limit,
                        "offset": offset,
                        "sort": "+id",
                        "select": (
                            "id,name,ip,status,version,"
                            "os.name,os.version,os.platform,lastKeepAlive"
                        ),
                    },
                    headers={"authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as error:
                raise WazuhError(f"manager agents request failed: {error}") from error

            if response.status_code in (401, 403):
                # A cached token may have been revoked; retry once with a fresh one.
                self._manager_token = None
                token = await self._manager_token_value()
                try:
                    response = await self._manager.get(
                        url,
                        params={
                            "limit": limit,
                            "offset": offset,
                            "sort": "+id",
                            "select": (
                                "id,name,ip,status,version,"
                                "os.name,os.version,os.platform,lastKeepAlive"
                            ),
                        },
                        headers={"authorization": f"Bearer {token}"},
                    )
                except httpx.HTTPError as error:
                    raise WazuhError(
                        f"manager agents request failed: {error}"
                    ) from error

            if response.status_code >= 400:
                raise WazuhError(
                    f"manager agents returned HTTP {response.status_code}"
                )

            try:
                payload = response.json()
            except ValueError as error:
                raise WazuhError("manager returned a non-JSON response") from error

            data = payload.get("data", {})
            items = data.get("affected_items", [])
            if not isinstance(items, list):
                raise WazuhError("manager agents response is malformed")

            agents.extend(item for item in items if isinstance(item, dict))

            total = data.get("total_affected_items")
            if not isinstance(total, int) or len(items) < limit:
                break
            if len(agents) >= total:
                break
            offset += limit

        return agents

    async def aclose(self) -> None:
        await self._indexer.aclose()
        await self._manager.aclose()

    async def __aenter__(self) -> WazuhClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


def parse_wazuh_timestamp(value: object) -> datetime | None:
    """Parse Wazuh ISO timestamps (`2026-11-13T10:00:00.123+0000`)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
