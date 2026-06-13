from __future__ import annotations

import httpx
import pytest

from neoshield.worker.client import (
    WorkerAuthError,
    WorkerClient,
    WorkerRequestError,
)


def client_with(handler: httpx.MockTransport) -> WorkerClient:
    return WorkerClient(
        "http://web:3000",
        "nsw_test_token_value",
        transport=handler,
    )


async def test_heartbeat_returns_worker_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer nsw_test_token_value"
        assert request.url.path == "/api/internal/worker/heartbeat"
        return httpx.Response(
            200,
            json={
                "data": {
                    "workerId": "0f1b9a3e-6a2f-4f0e-99c4-6c3f8b0e1a11",
                    "workspaceId": "6f1b9a3e-6a2f-4f0e-99c4-6c3f8b0e1a22",
                    "name": "scan-worker-1",
                    "scopes": ["worker:heartbeat"],
                    "heartbeatIntervalSeconds": 30,
                }
            },
        )

    heartbeat = await client_with(httpx.MockTransport(handler)).heartbeat(
        version="0.1.0", hostname="test-host"
    )

    assert heartbeat.name == "scan-worker-1"
    assert heartbeat.interval_seconds == 30
    assert heartbeat.scopes == ("worker:heartbeat",)


async def test_revoked_token_raises_auth_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "invalid_token"}})

    with pytest.raises(WorkerAuthError):
        await client_with(httpx.MockTransport(handler)).heartbeat(
            version="0.1.0", hostname="test-host"
        )


async def test_malformed_response_raises_request_error() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"unexpected": True}})

    with pytest.raises(WorkerRequestError):
        await client_with(httpx.MockTransport(handler)).heartbeat(
            version="0.1.0", hostname="test-host"
        )


async def test_registration_returns_token_once() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer bootstrap-secret"
        return httpx.Response(
            201,
            json={"data": {"workerId": "abc", "token": "nsw_issued"}},
        )

    token = await WorkerClient(
        "http://web:3000", None, transport=httpx.MockTransport(handler)
    ).register(
        bootstrap_token="bootstrap-secret",
        workspace_id="6f1b9a3e-6a2f-4f0e-99c4-6c3f8b0e1a22",
        name="worker",
        version="0.1.0",
        hostname="test-host",
    )

    assert token == "nsw_issued"
