"""Direct database access for the scan worker.

The worker holds a restricted PostgreSQL role: it may claim `scan_job` rows and
write `scan_run`, `finding`, `finding_evidence` and `finding_status_event`.
Drizzle in the web app owns the schema; this module only runs parameterized SQL.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from neoshield.worker.normalize import Finding

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
    config: dict[str, Any]


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
                       a.display_name, a.identifier, a.config
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
        self, job: ClaimedJob, target: AssetTarget, snapshot: dict[str, Any]
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
                    'repository', 'running', %(snapshot)s, '[]'::jsonb, now()
                )
                RETURNING id
                """,
                {
                    "workspace_id": job.workspace_id,
                    "project_id": target.project_id,
                    "asset_id": target.asset_id,
                    "job_id": job.id,
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
                        connection, job, target, run_id, finding
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
        job: ClaimedJob,
        target: AssetTarget,
        run_id: str,
        finding: Finding,
    ) -> None:
        cursor = await connection.execute(
            """
            INSERT INTO finding (
                workspace_id, project_id, asset_id, source, source_tool,
                source_rule_id, stable_key, title, description, category,
                severity, confidence, cve_id, cvss_score, remediation,
                references, first_seen_at, last_seen_at, occurrence_count,
                missed_scan_count, updated_at
            )
            VALUES (
                %(workspace_id)s, %(project_id)s, %(asset_id)s,
                'github'::finding_source, %(source_tool)s, %(rule_id)s,
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
                references = EXCLUDED.references,
                source_rule_id = EXCLUDED.source_rule_id,
                last_seen_at = now(),
                occurrence_count = finding.occurrence_count + 1,
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
                "workspace_id": job.workspace_id,
                "project_id": target.project_id,
                "asset_id": target.asset_id,
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

    async def _resolve_stale(
        self,
        connection: Any,
        asset_id: str,
        successful_tools: list[str],
        seen_keys: list[str],
        stale_after: int,
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
            """,
            {
                "asset_id": asset_id,
                "tools": successful_tools,
                "seen": seen_keys,
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
