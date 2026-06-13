import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from neoshield.config import Settings
from neoshield.worker.wazuh_client import WazuhClient
from neoshield.worker.wazuh_normalize import normalize_alert


def make_settings() -> Settings:
    return Settings(
        wazuh_enabled=True,
        wazuh_indexer_url="https://indexer.test:9200",
        wazuh_indexer_username="admin",
        wazuh_indexer_password="secret",
        wazuh_indexer_verify_tls=False,
        wazuh_manager_url=None,
    )


def alert(agent_id: str, rule_id: str = "5710") -> dict[str, Any]:
    return {
        "_id": f"alert-{agent_id}-{rule_id}",
        "_index": "wazuh-alerts-4.x-2026.11.13",
        "_source": {
            "timestamp": "2026-11-13T19:03:04.844+0000",
            "agent": {"id": agent_id, "name": f"agent-{agent_id}"},
            "rule": {
                "id": rule_id,
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user",
                "groups": ["syslog", "sshd", "authentication_failed"],
            },
            "data": {"srcuser": "labuser", "srcip": "127.0.0.1"},
            "location": "/var/log/auth.log",
            "full_log": "raw log line that must never be persisted",
        },
    }


def mock_client(
    captured: dict[str, Any], hits: list[dict[str, Any]]
) -> WazuhClient:
    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"hits": {"hits": hits}})

    return WazuhClient(
        make_settings(), index_transport=httpx.MockTransport(handler)
    )


async def test_search_excludes_manager_alerts_and_normalizes_endpoints() -> None:
    captured: dict[str, Any] = {}
    client = mock_client(captured, [alert("001"), alert("000")])
    try:
        hits = await client.search_alerts(
            after=datetime.now(UTC) - timedelta(minutes=5),
            min_level=5,
            size=10,
        )
    finally:
        await client.aclose()

    filters = captured["body"]["query"]["bool"]["filter"]
    assert {"bool": {"must_not": [{"term": {"agent.id": "000"}}]}} in filters
    assert "wazuh-alerts-*" in captured["url"]

    alerts = [a for a in (normalize_alert(hit, min_level=5) for hit in hits) if a]
    assert [a.agent_id for a in alerts] == ["001"]

    normalized = alerts[0]
    assert normalized.category == "authentication"
    assert normalized.severity == "low"
    assert normalized.finding is not None
    assert normalized.finding.stable_key == (
        "wazuh|auth|001|5710|127.0.0.1|labuser"
    )
    assert "full_log" not in json.dumps(normalized.evidence)


async def test_search_can_scope_a_single_agent_without_manager_exclusion() -> None:
    captured: dict[str, Any] = {}
    client = mock_client(captured, [alert("001")])
    try:
        await client.search_alerts(
            after=datetime.now(UTC) - timedelta(minutes=5),
            min_level=0,
            size=10,
            agent_id="001",
        )
    finally:
        await client.aclose()

    filters = captured["body"]["query"]["bool"]["filter"]
    assert {"term": {"agent.id": "001"}} in filters
    assert not any("must_not" in entry for entry in filters if isinstance(entry, dict))
