from fastapi.testclient import TestClient

from neoshield.api.main import app


def test_health_reports_service_and_worker_state() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "ok"
    assert body["service"] == "neoshield-python"
    assert body["worker"]["configured"] is False
    assert body["worker"]["online"] is False
    assert body["capabilities"]["jobClaiming"] is False

    # Never expose credentials, even when the worker is unconfigured.
    serialized = response.text
    assert "Bearer" not in serialized
    assert "token" not in serialized.lower()
