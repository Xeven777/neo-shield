"""Direct database access for the scan worker.

The worker holds a restricted PostgreSQL role: it may claim `scan_job` rows and
write `scan_run`, `finding`, `finding_evidence` and `finding_status_event`.
Drizzle in the web app owns the schema; this module only runs parameterized SQL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from neoshield.worker.network_scan import ScanOutcome
from neoshield.worker.normalize import Finding
from neoshield.worker.wazuh_normalize import (
    AgentInfo,
    WazuhAlert,
    agent_disconnected_finding,
)

logger = logging.getLogger(__name__)

STALE_NOTE = "Absent from two consecutive successful scans"


class StoreError(RuntimeError):
    """A database operation failed. Messages contain no scanner payloads."""


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    id: str
    workspace_id: str
    asset_id: str
    attempts: int
    max_attempts: int


@dataclass(frozen=True, slots=True)
class AssetTarget:
    asset_id: str
    workspace_id: str
    project_id: str
    display_name: str
    identifier: str
    asset_type: str
    config: dict[str, Any]


@dataclass(frozen=True, slots=True)
class WazuhIntegration:
    id: str
    workspace_id: str
    project_id: str
    min_level: int
    auto_provision: bool
    cursor: datetime | None
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class WazuhIngestResult:
    received: int = 0
    events: int = 0
    findings: int = 0
    duplicates: int = 0


@dataclass(frozen=True, slots=True)
class AgentSyncResult:
    agents: int = 0
    disconnected: int = 0
    reconnected: int = 0


class ScanStore:
    def __init__(self, database_url: str, *, min_size: int = 1, max_size: int = 4):
        self._pool = AsyncConnectionPool(
            database_url,
            min_size=min_size,
            max_size=max_size,
            open=False,
            kwargs={"row_factory": dict_row, "autocommit": False},
        )

    async def open(self) -> None:
        await self._pool.open(wait=True, timeout=15)

    async def close(self) -> None:
        await self._pool.close()

    async def claim(self, worker_id: str, lease_seconds: int) -> ClaimedJob | None:
        async with self._pool.connection() as connection:
            async with connection.transaction():
                await connection.execute(
                    """
                    UPDATE scan_job
                    SET status = 'failed',
                        completed_at = now(),
                        lease_expires_at = NULL,
                        error_summary = 'Lease expired after the maximum attempts',
                        updated_at = now()
                    WHERE status IN ('leased', 'running')
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at < now()
                      AND attempts >= max_attempts
                    """
                )

                cursor = await connection.execute(
                    """
                    WITH candidate AS (
                        SELECT id
                        FROM scan_job
                        WHERE (
                                status = 'queued' AND available_at <= now()
                            ) OR (
                                status IN ('leased', 'running')
                                AND lease_expires_at IS NOT NULL
                                AND lease_expires_at < now()
                            )
                        ORDER BY available_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE scan_job AS job
                    SET status = 'leased',
                        attempts = job.attempts + 1,
                        leased_by_worker_id = %(worker_id)s,
                        lease_expires_at = now() + make_interval(secs => %(lease)s),
                        error_summary = NULL,
                        updated_at = now()
                    FROM candidate
                    WHERE job.id = candidate.id
                      AND job.attempts < job.max_attempts
                    RETURNING job.id, job.workspace_id, job.asset_id,
                              job.attempts, job.max_attempts
                    """,
                    {"worker_id": worker_id, "lease": lease_seconds},
                )
                row = await cursor.fetchone()

        if row is None:
            return None

        return ClaimedJob(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            asset_id=str(row["asset_id"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
        )

    async def load_target(self, job: ClaimedJob) -> AssetTarget | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                SELECT a.id AS asset_id, p.workspace_id, p.id AS project_id,
                       a.display_name, a.identifier, a.type AS asset_type,
                       a.config
                FROM asset AS a
                JOIN project AS p ON p.id = a.project_id
                WHERE a.id = %(asset_id)s AND p.workspace_id = %(workspace_id)s
                """,
                {"asset_id": job.asset_id, "workspace_id": job.workspace_id},
            )
            row = await cursor.fetchone()

        if row is None:
            return None

        config = row["config"] if isinstance(row["config"], dict) else {}
        return AssetTarget(
            asset_id=str(row["asset_id"]),
            workspace_id=str(row["workspace_id"]),
            project_id=str(row["project_id"]),
            display_name=str(row["display_name"]),
            identifier=str(row["identifier"]),
            asset_type=str(row["asset_type"]),
            config=config,
        )

    async def mark_running(
        self, job_id: str, worker_id: str, lease_seconds: int
    ) -> None:
        async with self._pool.connection() as connection:
            await connection.execute(
                """
                UPDATE scan_job
                SET status = 'running',
                    started_at = COALESCE(started_at, now()),
                    lease_expires_at = now() + make_interval(secs => %(lease)s),
                    updated_at = now()
                WHERE id = %(job_id)s
                  AND leased_by_worker_id = %(worker_id)s
                  AND status IN ('leased', 'running')
                """,
                {
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "lease": lease_seconds,
                },
            )
            await connection.commit()

    async def renew_lease(
        self, job_id: str, worker_id: str, lease_seconds: int
    ) -> bool:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                UPDATE scan_job
                SET lease_expires_at = now() + make_interval(secs => %(lease)s),
                    updated_at = now()
                WHERE id = %(job_id)s
                  AND leased_by_worker_id = %(worker_id)s
                  AND status IN ('leased', 'running')
                """,
                {
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "lease": lease_seconds,
                },
            )
            await connection.commit()
            return cursor.rowcount > 0

    async def start_run(
        self,
        job: ClaimedJob,
        target: AssetTarget,
        snapshot: dict[str, Any],
        *,
        scanner: str = "repository",
    ) -> str:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                INSERT INTO scan_run (
                    workspace_id, project_id, asset_id, scan_job_id, scanner,
                    status, target_snapshot, tools, started_at
                )
                VALUES (
                    %(workspace_id)s, %(project_id)s, %(asset_id)s, %(job_id)s,
                    %(scanner)s, 'running', %(snapshot)s, '[]'::jsonb, now()
                )
                RETURNING id
                """,
                {
                    "workspace_id": job.workspace_id,
                    "project_id": target.project_id,
                    "asset_id": target.asset_id,
                    "job_id": job.id,
                    "scanner": scanner,
                    "snapshot": Jsonb(snapshot),
                },
            )
            row = await cursor.fetchone()
            await connection.commit()

        if row is None:
            raise StoreError("scan run could not be created")
        return str(row["id"])

    async def complete_success(
        self,
        job: ClaimedJob,
        target: AssetTarget,
        run_id: str,
        findings: list[Finding],
        tools: list[dict[str, object]],
        successful_tools: list[str],
        *,
        stale_after: int = 2,
    ) -> int:
        seen_keys = [finding.stable_key for finding in findings]

        async with self._pool.connection() as connection:
            async with connection.transaction():
                for finding in findings:
                    await self._upsert_finding(
                        connection,
                        workspace_id=job.workspace_id,
                        project_id=target.project_id,
                        asset_id=target.asset_id,
                        run_id=run_id,
                        finding=finding,
                    )

                if successful_tools:
                    await self._resolve_stale(
                        connection,
                        target.asset_id,
                        successful_tools,
                        seen_keys,
                        stale_after,
                    )

                await connection.execute(
                    """
                    UPDATE scan_run
                    SET status = 'completed',
                        tools = %(tools)s,
                        finding_count = %(count)s,
                        completed_at = now()
                    WHERE id = %(run_id)s
                    """,
                    {
                        "tools": Jsonb(tools),
                        "count": len(findings),
                        "run_id": run_id,
                    },
                )

                await connection.execute(
                    """
                    UPDATE scan_job
                    SET status = 'completed',
                        completed_at = now(),
                        lease_expires_at = NULL,
                        error_summary = NULL,
                        updated_at = now()
                    WHERE id = %(job_id)s
                    """,
                    {"job_id": job.id},
                )

        return len(findings)

    async def complete_ingest_run(
        self,
        job: ClaimedJob,
        run_id: str,
        *,
        tools: list[dict[str, object]],
        finding_count: int,
        snapshot: dict[str, Any],
    ) -> None:
        """Complete a run whose findings were already ingested in a batch."""
        async with self._pool.connection() as connection:
            async with connection.transaction():
                await connection.execute(
                    """
                    UPDATE scan_run
                    SET status = 'completed',
                        tools = %(tools)s,
                        finding_count = %(count)s,
                        target_snapshot = %(snapshot)s,
                        completed_at = now()
                    WHERE id = %(run_id)s
                    """,
                    {
                        "tools": Jsonb(tools),
                        "count": finding_count,
                        "snapshot": Jsonb(snapshot),
                        "run_id": run_id,
                    },
                )
                await connection.execute(
                    """
                    UPDATE scan_job
                    SET status = 'completed',
                        completed_at = now(),
                        lease_expires_at = NULL,
                        error_summary = NULL,
                        updated_at = now()
                    WHERE id = %(job_id)s
                    """,
                    {"job_id": job.id},
                )

    async def complete_failure(
        self,
        job: ClaimedJob,
        run_id: str | None,
        error: str,
        tools: list[dict[str, object]],
        *,
        retryable: bool,
    ) -> None:
        summary = error.replace("\n", " ")[:500] or "Scan failed"

        async with self._pool.connection() as connection:
            async with connection.transaction():
                if run_id is not None:
                    await connection.execute(
                        """
                        UPDATE scan_run
                        SET status = 'failed',
                            tools = %(tools)s,
                            error_summary = %(error)s,
                            completed_at = now()
                        WHERE id = %(run_id)s
                        """,
                        {
                            "tools": Jsonb(tools),
                            "error": summary,
                            "run_id": run_id,
                        },
                    )

                if retryable and job.attempts < job.max_attempts:
                    await connection.execute(
                        """
                        UPDATE scan_job
                        SET status = 'queued',
                            available_at = now() + make_interval(
                                secs => %(delay)s
                            ),
                            lease_expires_at = NULL,
                            leased_by_worker_id = NULL,
                            error_summary = %(error)s,
                            updated_at = now()
                        WHERE id = %(job_id)s
                        """,
                        {
                            "delay": min(300, 30 * job.attempts),
                            "error": summary,
                            "job_id": job.id,
                        },
                    )
                else:
                    await connection.execute(
                        """
                        UPDATE scan_job
                        SET status = 'failed',
                            completed_at = now(),
                            lease_expires_at = NULL,
                            error_summary = %(error)s,
                            updated_at = now()
                        WHERE id = %(job_id)s
                        """,
                        {"error": summary, "job_id": job.id},
                    )

    async def _upsert_finding(
        self,
        connection: Any,
        *,
        workspace_id: str,
        project_id: str,
        asset_id: str,
        run_id: str | None,
        finding: Finding,
        increment_occurrence: bool = True,
    ) -> str:
        cursor = await connection.execute(
            """
            INSERT INTO finding (
                workspace_id, project_id, asset_id, source, source_tool,
                source_rule_id, stable_key, title, description, category,
                severity, confidence, cve_id, cvss_score, remediation,
                "references", first_seen_at, last_seen_at, occurrence_count,
                missed_scan_count, updated_at
            )
            VALUES (
                %(workspace_id)s, %(project_id)s, %(asset_id)s,
                %(source)s::finding_source, %(source_tool)s, %(rule_id)s,
                %(stable_key)s, %(title)s, %(description)s, %(category)s,
                %(severity)s::finding_severity, %(confidence)s::finding_confidence,
                %(cve_id)s, %(cvss)s, %(remediation)s, %(references)s,
                now(), now(), 1, 0, now()
            )
            ON CONFLICT (asset_id, stable_key) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                confidence = EXCLUDED.confidence,
                cve_id = EXCLUDED.cve_id,
                cvss_score = EXCLUDED.cvss_score,
                remediation = EXCLUDED.remediation,
                "references" = EXCLUDED."references",
                source_rule_id = EXCLUDED.source_rule_id,
                last_seen_at = now(),
                occurrence_count = finding.occurrence_count + CASE
                    WHEN %(increment)s THEN 1 ELSE 0
                END,
                missed_scan_count = 0,
                status = CASE
                    WHEN finding.status = 'resolved' THEN 'open'::finding_status
                    ELSE finding.status
                END,
                resolved_at = CASE
                    WHEN finding.status = 'resolved' THEN NULL
                    ELSE finding.resolved_at
                END,
                updated_at = now()
            RETURNING id
            """,
            {
                "workspace_id": workspace_id,
                "project_id": project_id,
                "asset_id": asset_id,
                "source": finding.source,
                "source_tool": finding.source_tool,
                "rule_id": finding.source_rule_id,
                "stable_key": finding.stable_key,
                "title": finding.title,
                "description": finding.description,
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "cve_id": finding.cve_id,
                "cvss": finding.cvss_score,
                "remediation": finding.remediation,
                "references": Jsonb(finding.references),
                "increment": increment_occurrence,
            },
        )
        row = await cursor.fetchone()
        if row is None:
            raise StoreError("finding upsert returned no id")

        await connection.execute(
            """
            INSERT INTO finding_evidence (
                finding_id, scan_run_id, file_path, package_name,
                package_version, fixed_version, evidence
            )
            VALUES (
                %(finding_id)s, %(run_id)s, %(file_path)s, %(package_name)s,
                %(package_version)s, %(fixed_version)s, %(evidence)s
            )
            ON CONFLICT (finding_id) DO UPDATE SET
                scan_run_id = EXCLUDED.scan_run_id,
                file_path = EXCLUDED.file_path,
                package_name = EXCLUDED.package_name,
                package_version = EXCLUDED.package_version,
                fixed_version = EXCLUDED.fixed_version,
                evidence = EXCLUDED.evidence
            """,
            {
                "finding_id": row["id"],
                "run_id": run_id,
                "file_path": finding.file_path,
                "package_name": finding.package_name,
                "package_version": finding.package_version,
                "fixed_version": finding.fixed_version,
                "evidence": Jsonb(finding.evidence),
            },
        )

        return str(row["id"])

    async def _resolve_stale(
        self,
        connection: Any,
        asset_id: str,
        successful_tools: list[str],
        seen_keys: list[str],
        stale_after: int,
        *,
        categories: list[str] | None = None,
    ) -> None:
        await connection.execute(
            """
            UPDATE finding
            SET missed_scan_count = missed_scan_count + 1,
                updated_at = now()
            WHERE asset_id = %(asset_id)s
              AND source_tool = ANY(%(tools)s)
              AND NOT (stable_key = ANY(%(seen)s))
              AND status NOT IN ('resolved', 'accepted_risk', 'false_positive')
              AND (
                  %(categories)s::text[] IS NULL
                  OR category = ANY(%(categories)s::text[])
              )
            """,
            {
                "asset_id": asset_id,
                "tools": successful_tools,
                "seen": seen_keys,
                "categories": categories,
            },
        )

        await connection.execute(
            """
            WITH due AS (
                SELECT id, status
                FROM finding
                WHERE asset_id = %(asset_id)s
                  AND missed_scan_count >= %(threshold)s
                  AND status NOT IN (
                      'resolved', 'accepted_risk', 'false_positive'
                  )
            ), recorded AS (
                INSERT INTO finding_status_event (
                    finding_id, from_status, to_status, note
                )
                SELECT id, status, 'resolved'::finding_status, %(note)s
                FROM due
            )
            UPDATE finding
            SET status = 'resolved'::finding_status,
                resolved_at = now(),
                updated_at = now()
            WHERE id IN (SELECT id FROM due)
            """,
            {
                "asset_id": asset_id,
                "note": STALE_NOTE,
                "threshold": max(1, stale_after),
            },
        )

    # ------------------------------------------------------------------
    # Wazuh endpoint monitoring (Phase 2)
    # ------------------------------------------------------------------

    async def list_wazuh_integrations(
        self, *, default_min_level: int = 5
    ) -> list[WazuhIntegration]:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                SELECT id, workspace_id, project_id, metadata, sync_cursor
                FROM integration
                WHERE provider = 'wazuh'
                  AND project_id IS NOT NULL
                  AND status IN ('pending', 'connected', 'error')
                ORDER BY created_at ASC
                """
            )
            rows = await cursor.fetchall()

        integrations: list[WazuhIntegration] = []
        for row in rows:
            metadata = row["metadata"] if isinstance(row["metadata"], dict) else {}
            min_level = _as_int(metadata.get("minLevel"), default_min_level)
            integrations.append(
                WazuhIntegration(
                    id=str(row["id"]),
                    workspace_id=str(row["workspace_id"]),
                    project_id=str(row["project_id"]),
                    min_level=max(0, min(16, min_level)),
                    auto_provision=metadata.get("autoProvision") is not False,
                    cursor=row["sync_cursor"],
                    metadata=metadata,
                )
            )
        return integrations

    async def get_wazuh_integration_for_workspace(
        self, workspace_id: str, *, default_min_level: int = 5
    ) -> WazuhIntegration | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                SELECT id, workspace_id, project_id, metadata, sync_cursor
                FROM integration
                WHERE provider = 'wazuh'
                  AND workspace_id = %(workspace_id)s
                  AND project_id IS NOT NULL
                  AND status IN ('pending', 'connected', 'error')
                ORDER BY created_at ASC
                LIMIT 1
                """,
                {"workspace_id": workspace_id},
            )
            row = await cursor.fetchone()

        if row is None:
            return None

        metadata = row["metadata"] if isinstance(row["metadata"], dict) else {}
        return WazuhIntegration(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            project_id=str(row["project_id"]),
            min_level=max(
                0, min(16, _as_int(metadata.get("minLevel"), default_min_level))
            ),
            auto_provision=metadata.get("autoProvision") is not False,
            cursor=row["sync_cursor"],
            metadata=metadata,
        )

    async def save_wazuh_integration_state(
        self,
        integration_id: str,
        *,
        status: str,
        cursor_time: datetime | None = None,
        last_error: str | None = None,
        synced: bool = False,
        metadata_patch: dict[str, Any] | None = None,
    ) -> None:
        patch = metadata_patch or {}
        async with self._pool.connection() as connection:
            await connection.execute(
                """
                UPDATE integration
                SET status = %(status)s,
                    sync_cursor = COALESCE(%(cursor)s, sync_cursor),
                    last_synced_at = CASE
                        WHEN %(synced)s THEN now() ELSE last_synced_at
                    END,
                    last_error = %(error)s,
                    metadata = metadata || %(patch)s,
                    updated_at = now()
                WHERE id = %(id)s
                """,
                {
                    "id": integration_id,
                    "status": status,
                    "cursor": cursor_time,
                    "error": (last_error or "")[:500] or None,
                    "synced": synced,
                    "patch": Jsonb(patch),
                },
            )
            await connection.commit()

    async def _ensure_endpoint_asset(
        self,
        connection: Any,
        integration: WazuhIntegration,
        agent: AgentInfo,
        *,
        auto_provision: bool,
    ) -> str | None:
        identifier = f"wazuh:{agent.agent_id}"
        display_name = agent.name or f"wazuh-agent-{agent.agent_id}"
        config = {
            "provider": "wazuh",
            "agentId": agent.agent_id,
            "agentName": display_name,
            "hostname": display_name,
            "ipAddress": agent.ip_address,
            "osName": agent.os_name,
            "osVersion": agent.os_version,
            "osPlatform": agent.os_platform,
            "agentVersion": agent.version,
        }

        if auto_provision:
            cursor = await connection.execute(
                """
                INSERT INTO asset (
                    project_id, type, display_name, identifier, config, enabled
                )
                VALUES (
                    %(project)s, 'endpoint'::asset_type, %(name)s,
                    %(identifier)s, %(config)s, true
                )
                ON CONFLICT (project_id, type, identifier) DO UPDATE SET
                    display_name = CASE
                        WHEN EXCLUDED.display_name = '' THEN asset.display_name
                        ELSE EXCLUDED.display_name
                    END,
                    config = asset.config || EXCLUDED.config,
                    updated_at = now()
                RETURNING id
                """,
                {
                    "project": integration.project_id,
                    "name": display_name,
                    "identifier": identifier,
                    "config": Jsonb(
                        {key: value for key, value in config.items() if value}
                    ),
                },
            )
            row = await cursor.fetchone()
        else:
            cursor = await connection.execute(
                """
                SELECT id
                FROM asset
                WHERE project_id = %(project)s
                  AND type = 'endpoint'
                  AND identifier = %(identifier)s
                """,
                {
                    "project": integration.project_id,
                    "identifier": identifier,
                },
            )
            row = await cursor.fetchone()
            if row is not None:
                await connection.execute(
                    """
                    UPDATE asset
                    SET config = config || %(config)s, updated_at = now()
                    WHERE id = %(id)s
                    """,
                    {
                        "id": row["id"],
                        "config": Jsonb(
                            {
                                key: value
                                for key, value in config.items()
                                if value
                            }
                        ),
                    },
                )

        if row is None:
            return None

        asset_id = str(row["id"])
        await connection.execute(
            """
            INSERT INTO endpoint_agent (
                workspace_id, asset_id, provider, external_id, name,
                ip_address, os_name, os_version, os_platform, architecture,
                agent_version, status, last_seen_at, config
            )
            VALUES (
                %(workspace)s, %(asset)s, 'wazuh', %(external)s, %(name)s,
                %(ip)s, %(os_name)s, %(os_version)s, %(os_platform)s,
                %(architecture)s, %(version)s, %(status)s, %(last_seen)s,
                %(config)s
            )
            ON CONFLICT (asset_id, provider, external_id) DO UPDATE SET
                name = EXCLUDED.name,
                ip_address = COALESCE(EXCLUDED.ip_address, endpoint_agent.ip_address),
                os_name = COALESCE(EXCLUDED.os_name, endpoint_agent.os_name),
                os_version = COALESCE(EXCLUDED.os_version, endpoint_agent.os_version),
                os_platform = COALESCE(
                    EXCLUDED.os_platform, endpoint_agent.os_platform
                ),
                architecture = COALESCE(
                    EXCLUDED.architecture, endpoint_agent.architecture
                ),
                agent_version = COALESCE(
                    EXCLUDED.agent_version, endpoint_agent.agent_version
                ),
                status = CASE
                    WHEN EXCLUDED.status = 'unknown' THEN endpoint_agent.status
                    ELSE EXCLUDED.status
                END,
                last_seen_at = COALESCE(
                    EXCLUDED.last_seen_at, endpoint_agent.last_seen_at
                ),
                config = endpoint_agent.config || EXCLUDED.config,
                updated_at = now()
            """,
            {
                "workspace": integration.workspace_id,
                "asset": asset_id,
                "external": agent.agent_id,
                "name": display_name,
                "ip": agent.ip_address,
                "os_name": agent.os_name,
                "os_version": agent.os_version,
                "os_platform": agent.os_platform,
                "architecture": agent.architecture,
                "version": agent.version,
                "status": agent.status or "unknown",
                "last_seen": agent.last_seen,
                "config": Jsonb(
                    {
                        "agentId": agent.agent_id,
                        "status": agent.status,
                    }
                ),
            },
        )
        return asset_id

    async def ingest_wazuh_alerts(
        self,
        integration: WazuhIntegration,
        alerts: list[WazuhAlert],
        *,
        run_id: str | None = None,
    ) -> WazuhIngestResult:
        events = findings = duplicates = 0

        async with self._pool.connection() as connection:
            async with connection.transaction():
                for alert in alerts:
                    agent = AgentInfo(
                        agent_id=alert.agent_id,
                        name=alert.agent_name,
                        ip_address=alert.agent_ip,
                        last_seen=alert.event_time,
                    )
                    asset_id = await self._ensure_endpoint_asset(
                        connection,
                        integration,
                        agent,
                        auto_provision=integration.auto_provision,
                    )
                    if asset_id is None:
                        continue

                    cursor = await connection.execute(
                        """
                        INSERT INTO security_event (
                            workspace_id, project_id, asset_id, source,
                            source_tool, external_id, event_time, rule_id,
                            rule_level, severity, category, title, description,
                            agent_id, agent_name, source_ip, evidence
                        )
                        VALUES (
                            %(workspace)s, %(project)s, %(asset)s,
                            'wazuh'::finding_source, 'wazuh', %(external)s,
                            %(event_time)s, %(rule_id)s, %(rule_level)s,
                            %(severity)s::finding_severity, %(category)s,
                            %(title)s, %(description)s, %(agent_id)s,
                            %(agent_name)s, %(source_ip)s, %(evidence)s
                        )
                        ON CONFLICT (
                            workspace_id, source_tool, external_id
                        ) DO NOTHING
                        RETURNING id
                        """,
                        {
                            "workspace": integration.workspace_id,
                            "project": integration.project_id,
                            "asset": asset_id,
                            "external": alert.external_id,
                            "event_time": alert.event_time,
                            "rule_id": alert.rule_id,
                            "rule_level": alert.rule_level,
                            "severity": alert.severity,
                            "category": alert.category,
                            "title": alert.title,
                            "description": alert.description,
                            "agent_id": alert.agent_id,
                            "agent_name": alert.agent_name,
                            "source_ip": alert.source_ip,
                            "evidence": Jsonb(alert.evidence),
                        },
                    )
                    row = await cursor.fetchone()
                    if row is None:
                        duplicates += 1
                        continue

                    events += 1
                    event_id = str(row["id"])

                    if alert.agent_status:
                        await connection.execute(
                            """
                            UPDATE endpoint_agent
                            SET status = %(status)s,
                                last_seen_at = %(last_seen)s,
                                updated_at = now()
                            WHERE asset_id = %(asset)s
                              AND provider = 'wazuh'
                              AND external_id = %(external)s
                            """,
                            {
                                "status": alert.agent_status,
                                "last_seen": alert.event_time,
                                "asset": asset_id,
                                "external": alert.agent_id,
                            },
                        )

                    if alert.finding is not None:
                        finding_id = await self._upsert_finding(
                            connection,
                            workspace_id=integration.workspace_id,
                            project_id=integration.project_id,
                            asset_id=asset_id,
                            run_id=run_id,
                            finding=alert.finding,
                        )
                        findings += 1
                        await connection.execute(
                            """
                            UPDATE security_event
                            SET finding_id = %(finding)s
                            WHERE id = %(event)s
                            """,
                            {"finding": finding_id, "event": event_id},
                        )

        return WazuhIngestResult(
            received=len(alerts),
            events=events,
            findings=findings,
            duplicates=duplicates,
        )

    async def sync_wazuh_agents(
        self,
        integration: WazuhIntegration,
        agents: list[AgentInfo],
    ) -> AgentSyncResult:
        count = disconnected = reconnected = 0

        async with self._pool.connection() as connection:
            async with connection.transaction():
                for agent in agents:
                    asset_id = await self._ensure_endpoint_asset(
                        connection,
                        integration,
                        agent,
                        auto_provision=integration.auto_provision,
                    )
                    if asset_id is None:
                        continue
                    count += 1

                    if agent.status in {
                        "disconnected",
                        "pending",
                        "never_connected",
                    }:
                        finding = agent_disconnected_finding(agent)
                        if finding is not None:
                            await self._upsert_finding(
                                connection,
                                workspace_id=integration.workspace_id,
                                project_id=integration.project_id,
                                asset_id=asset_id,
                                run_id=None,
                                finding=finding,
                                increment_occurrence=False,
                            )
                            disconnected += 1
                    else:
                        cursor = await connection.execute(
                            """
                            WITH due AS (
                                SELECT id, status
                                FROM finding
                                WHERE asset_id = %(asset)s
                                  AND stable_key = 'wazuh|agent|disconnected'
                                  AND status NOT IN (
                                      'resolved', 'accepted_risk',
                                      'false_positive'
                                  )
                            ), recorded AS (
                                INSERT INTO finding_status_event (
                                    finding_id, from_status, to_status, note
                                )
                                SELECT id, status,
                                       'resolved'::finding_status,
                                       'Wazuh agent reconnected'
                                FROM due
                            )
                            UPDATE finding
                            SET status = 'resolved'::finding_status,
                                resolved_at = now(),
                                updated_at = now()
                            WHERE id IN (SELECT id FROM due)
                            RETURNING id
                            """,
                            {"asset": asset_id},
                        )
                        reconnected += len(await cursor.fetchall())

        return AgentSyncResult(
            agents=count,
            disconnected=disconnected,
            reconnected=reconnected,
        )

    async def latest_security_event_time(
        self, asset_id: str
    ) -> datetime | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                SELECT max(event_time) AS event_time
                FROM security_event
                WHERE asset_id = %(asset)s AND source_tool = 'wazuh'
                """,
                {"asset": asset_id},
            )
            row = await cursor.fetchone()

        return row["event_time"] if row else None

    # ------------------------------------------------------------------
    # Authorized network discovery (Phase 2)
    # ------------------------------------------------------------------

    async def complete_network_success(
        self,
        job: ClaimedJob,
        target: AssetTarget,
        run_id: str,
        outcome: ScanOutcome,
        tools: list[dict[str, object]],
        *,
        stale_after: int = 2,
    ) -> int:
        seen_keys = [finding.stable_key for finding in outcome.findings]
        observed_hosts = {host.address for host in outcome.hosts}
        observed_services = {
            (host.address, service.port, service.protocol)
            for host in outcome.hosts
            for service in host.services
        }
        profile = str(outcome.snapshot.get("profile") or "services")
        service_complete = bool(outcome.snapshot.get("serviceScanComplete"))
        scanned_addresses = [
            str(address)
            for address in (outcome.snapshot.get("serviceScannedAddresses") or [])
        ]

        async with self._pool.connection() as connection:
            async with connection.transaction():
                cursor = await connection.execute(
                    """
                    SELECT address FROM network_host WHERE asset_id = %(asset)s
                    """,
                    {"asset": target.asset_id},
                )
                existing_hosts = {
                    str(row["address"]) for row in await cursor.fetchall()
                }

                cursor = await connection.execute(
                    """
                    SELECT h.address, s.port, s.protocol
                    FROM network_service AS s
                    JOIN network_host AS h ON h.id = s.host_id
                    WHERE s.asset_id = %(asset)s
                    """,
                    {"asset": target.asset_id},
                )
                existing_services = {
                    (
                        str(row["address"]),
                        int(row["port"]),
                        str(row["protocol"]),
                    )
                    for row in await cursor.fetchall()
                }

                for host in outcome.hosts:
                    cursor = await connection.execute(
                        """
                        INSERT INTO network_host (
                            workspace_id, asset_id, address, hostname,
                            mac_address, vendor, status, first_seen_at,
                            last_seen_at, last_scan_run_id
                        )
                        VALUES (
                            %(workspace)s, %(asset)s, %(address)s, %(hostname)s,
                            %(mac)s, %(vendor)s, 'active', now(), now(),
                            %(run_id)s
                        )
                        ON CONFLICT (asset_id, address) DO UPDATE SET
                            hostname = COALESCE(
                                EXCLUDED.hostname, network_host.hostname
                            ),
                            mac_address = COALESCE(
                                EXCLUDED.mac_address, network_host.mac_address
                            ),
                            vendor = COALESCE(
                                EXCLUDED.vendor, network_host.vendor
                            ),
                            status = 'active',
                            last_seen_at = now(),
                            last_scan_run_id = EXCLUDED.last_scan_run_id,
                            updated_at = now()
                        RETURNING id
                        """,
                        {
                            "workspace": job.workspace_id,
                            "asset": target.asset_id,
                            "address": host.address,
                            "hostname": host.hostname,
                            "mac": host.mac_address,
                            "vendor": host.vendor,
                            "run_id": run_id,
                        },
                    )
                    host_row = await cursor.fetchone()
                    if host_row is None:
                        raise StoreError("network host upsert returned no id")
                    host_id = str(host_row["id"])

                    for service in host.services:
                        await connection.execute(
                            """
                            INSERT INTO network_service (
                                host_id, asset_id, port, protocol, service_name,
                                product, version, extra_info, cpe, status,
                                first_seen_at, last_seen_at, last_scan_run_id
                            )
                            VALUES (
                                %(host)s, %(asset)s, %(port)s, %(protocol)s,
                                %(name)s, %(product)s, %(version)s,
                                %(extra)s, %(cpe)s, 'active', now(), now(),
                                %(run_id)s
                            )
                            ON CONFLICT (host_id, port, protocol) DO UPDATE SET
                                service_name = COALESCE(
                                    EXCLUDED.service_name,
                                    network_service.service_name
                                ),
                                product = COALESCE(
                                    EXCLUDED.product, network_service.product
                                ),
                                version = COALESCE(
                                    EXCLUDED.version, network_service.version
                                ),
                                extra_info = COALESCE(
                                    EXCLUDED.extra_info,
                                    network_service.extra_info
                                ),
                                cpe = COALESCE(
                                    EXCLUDED.cpe, network_service.cpe
                                ),
                                status = 'active',
                                last_seen_at = now(),
                                last_scan_run_id = EXCLUDED.last_scan_run_id,
                                updated_at = now()
                            """,
                            {
                                "host": host_id,
                                "asset": target.asset_id,
                                "port": service.port,
                                "protocol": service.protocol,
                                "name": service.service,
                                "product": service.product,
                                "version": service.version,
                                "extra": service.extra_info,
                                "cpe": service.cpe,
                                "run_id": run_id,
                            },
                        )

                cursor = await connection.execute(
                    """
                    UPDATE network_host
                    SET status = 'missing', updated_at = now()
                    WHERE asset_id = %(asset)s
                      AND NOT (address = ANY(%(seen)s))
                      AND status <> 'missing'
                    RETURNING address
                    """,
                    {
                        "asset": target.asset_id,
                        "seen": sorted(observed_hosts),
                    },
                )
                missing_hosts = [
                    str(row["address"]) for row in await cursor.fetchall()
                ]

                missing_services: list[dict[str, object]] = []
                if service_complete and scanned_addresses:
                    cursor = await connection.execute(
                        """
                        UPDATE network_service AS s
                        SET status = 'missing', updated_at = now()
                        FROM network_host AS h
                        WHERE s.host_id = h.id
                          AND s.asset_id = %(asset)s
                          AND h.address = ANY(%(scanned)s)
                          AND s.last_scan_run_id IS DISTINCT FROM %(run_id)s
                          AND s.status <> 'missing'
                        RETURNING h.address, s.port, s.protocol
                        """,
                        {
                            "asset": target.asset_id,
                            "scanned": scanned_addresses,
                            "run_id": run_id,
                        },
                    )
                    missing_services = [
                        {
                            "address": str(row["address"]),
                            "port": int(row["port"]),
                            "protocol": str(row["protocol"]),
                        }
                        for row in await cursor.fetchall()
                    ]

                for finding in outcome.findings:
                    await self._upsert_finding(
                        connection,
                        workspace_id=job.workspace_id,
                        project_id=target.project_id,
                        asset_id=target.asset_id,
                        run_id=run_id,
                        finding=finding,
                    )

                categories = (
                    None
                    if profile == "services" and service_complete
                    else ["network_host"]
                )
                await self._resolve_stale(
                    connection,
                    target.asset_id,
                    ["nmap"],
                    seen_keys,
                    stale_after,
                    categories=categories,
                )

                new_hosts = sorted(observed_hosts - existing_hosts)
                new_services = sorted(observed_services - existing_services)

                snapshot = dict(outcome.snapshot)
                snapshot["diff"] = {
                    "newHosts": new_hosts[:50],
                    "missingHosts": missing_hosts[:50],
                    "newServices": [
                        {
                            "address": address,
                            "port": port,
                            "protocol": protocol,
                        }
                        for address, port, protocol in new_services[:100]
                    ],
                    "missingServices": missing_services[:100],
                    "newHostCount": len(new_hosts),
                    "missingHostCount": len(missing_hosts),
                    "newServiceCount": len(new_services),
                    "missingServiceCount": len(missing_services),
                }

                await connection.execute(
                    """
                    UPDATE scan_run
                    SET status = 'completed',
                        tools = %(tools)s,
                        finding_count = %(count)s,
                        target_snapshot = %(snapshot)s,
                        completed_at = now()
                    WHERE id = %(run_id)s
                    """,
                    {
                        "tools": Jsonb(tools),
                        "count": len(outcome.findings),
                        "snapshot": Jsonb(snapshot),
                        "run_id": run_id,
                    },
                )

                await connection.execute(
                    """
                    UPDATE scan_job
                    SET status = 'completed',
                        completed_at = now(),
                        lease_expires_at = NULL,
                        error_summary = NULL,
                        updated_at = now()
                    WHERE id = %(job_id)s
                    """,
                    {"job_id": job.id},
                )

        return len(outcome.findings)


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
