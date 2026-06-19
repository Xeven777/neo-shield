import asyncio

from neoshield.db.store import ScanStore
from neoshield.worker.normalize import Finding


class FakeCursor:
    async def fetchone(self):
        return {"id": "finding-1"}


class FakeConnection:
    def __init__(self) -> None:
        self.queries: list[str] = []
        self.params: list[dict[str, object]] = []

    async def execute(self, sql, params):
        self.queries.append(sql)
        self.params.append(params)
        return FakeCursor()


def make_store() -> ScanStore:
    return object.__new__(ScanStore)


def make_finding() -> Finding:
    return Finding(
        source_tool="gitleaks",
        source_rule_id="aws-access-token",
        stable_key="gitleaks|aws-access-token|src/config.ts|12",
        title="Hardcoded AWS key",
        description="A credential-like string was detected.",
        category="secret",
        severity="high",
    )


def test_upsert_records_reopen_status_event():
    connection = FakeConnection()
    store = make_store()

    asyncio.run(
        store._upsert_finding(
            connection,
            workspace_id="workspace-1",
            project_id="project-1",
            asset_id="asset-1",
            run_id="run-1",
            finding=make_finding(),
        )
    )

    sql = "\n".join(connection.queries)
    assert "WITH previous AS" in sql
    assert "INSERT INTO finding_status_event" in sql
    assert "WHERE previous.status = 'resolved'::finding_status" in sql
    assert connection.params[0]["reopen_note"]


def test_resolve_stale_verifies_fixed_remediation_on_success():
    connection = FakeConnection()
    store = make_store()

    asyncio.run(
        store._resolve_stale(
            connection,
            "asset-1",
            ["gitleaks"],
            ["some-other-key"],
            2,
            run_id="run-1",
        )
    )

    sql = "\n".join(connection.queries)
    assert "UPDATE remediation AS r" in sql
    assert "verified_scan_run_id = %(run_id)s" in sql
    assert "INSERT INTO remediation_event" in sql
    assert "r.updated_at <= (" in sql


def test_resolve_stale_without_run_never_verifies():
    connection = FakeConnection()
    store = make_store()

    asyncio.run(
        store._resolve_stale(
            connection,
            "asset-1",
            ["gitleaks"],
            ["some-other-key"],
            2,
        )
    )

    sql = "\n".join(connection.queries)
    assert "UPDATE remediation" not in sql
