"""Scan job execution.

One job at a time per worker: claim, fetch a tarball snapshot, run the scanners
and write normalized findings. Long scans renew the lease; results are written
in one transaction so a crash never leaves a half-ingested run.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from neoshield.config import Settings
from neoshield.db.store import AssetTarget, ClaimedJob, ScanStore, StoreError
from neoshield.worker.github_client import (
    GithubError,
    download_tarball,
    installation_token,
    resolve_commit,
    safe_extract,
)
from neoshield.worker.runner import WorkerState
from neoshield.worker.scanners import ScannerBinaries, run_all

logger = logging.getLogger(__name__)


@dataclass
class JobRunner:
    settings: Settings
    store: ScanStore
    state: WorkerState
    scanner_binaries: Callable[[], ScannerBinaries]

    async def run_forever(self, stop: asyncio.Event) -> None:
        logger.info(
            "job loop starting: poll=%ss lease=%ss",
            self.settings.job_poll_interval_seconds,
            self.settings.job_lease_seconds,
        )

        while not stop.is_set():
            worker_id = self.state.worker_id
            if worker_id is None:
                await self._pause(stop, 2.0)
                continue

            try:
                job = await self.store.claim(
                    worker_id, self.settings.job_lease_seconds
                )
            except Exception as error:  # noqa: BLE001 - keep the loop alive
                logger.warning("could not claim a scan job: %s", error)
                await self._pause(stop, 10.0)
                continue

            if job is None:
                await self._pause(stop, self.settings.job_poll_interval_seconds)
                continue

            logger.info(
                "claimed scan job %s (attempt %s/%s)",
                job.id,
                job.attempts,
                job.max_attempts,
            )
            try:
                await self._execute(job, worker_id)
            except Exception as error:  # noqa: BLE001 - always release the job
                logger.exception("scan job %s failed unexpectedly", job.id)
                await self._fail(
                    job,
                    None,
                    f"unexpected worker error: {error}",
                    retryable=True,
                )

    async def _execute(self, job: ClaimedJob, worker_id: str) -> None:
        target = await self.store.load_target(job)
        if target is None:
            await self._fail(job, None, "Asset is no longer available", retryable=False)
            return

        if not target.identifier.startswith("github:"):
            await self._fail(
                job,
                None,
                "Unsupported asset type for this worker",
                retryable=False,
            )
            return

        installation_id = target.config.get("installationId")
        full_name = target.config.get("fullName")
        default_branch = target.config.get("defaultBranch") or "main"

        if not isinstance(installation_id, str) or not isinstance(full_name, str):
            await self._fail(job, None, "Asset metadata is incomplete", retryable=False)
            return

        if not self.settings.github_app_id or not self.settings.github_private_key:
            await self._fail(
                job,
                None,
                "GitHub App credentials are not configured on the worker",
                retryable=False,
            )
            return

        binaries = self.scanner_binaries()
        if all(path is None for _, path in binaries.items()):
            await self._fail(
                job,
                None,
                "No scanner binaries are installed on this worker",
                retryable=False,
            )
            return

        await self.store.mark_running(
            job.id, worker_id, self.settings.job_lease_seconds
        )

        try:
            await self._scan(
                job,
                target,
                installation_id,
                full_name,
                str(default_branch),
                binaries,
            )
        except GithubError as error:
            await self._fail(job, None, str(error), retryable=True)
        except StoreError as error:
            await self._fail(job, None, str(error), retryable=True)

    async def _scan(
        self,
        job: ClaimedJob,
        target: AssetTarget,
        installation_id: str,
        full_name: str,
        ref: str,
        binaries: ScannerBinaries,
    ) -> None:
        run_id: str | None = None

        with tempfile.TemporaryDirectory(prefix="neoshield-scan-") as temporary:
            workdir = Path(temporary) / "repository"
            reports = Path(temporary) / "reports"
            archive = Path(temporary) / "repository.tar.gz"

            async with httpx.AsyncClient(timeout=60.0) as client:
                token = await installation_token(
                    client,
                    self.settings.github_app_id or "",
                    self.settings.github_private_key or "",
                    installation_id,
                )
                commit = await resolve_commit(client, full_name, ref, token)
                archive_bytes = await download_tarball(
                    client,
                    full_name,
                    commit,
                    token,
                    archive,
                    max_bytes=self.settings.max_archive_bytes,
                )

            files_extracted = safe_extract(
                archive,
                workdir,
                max_files=self.settings.max_extracted_files,
                max_file_bytes=self.settings.max_file_bytes,
                max_total_bytes=self.settings.max_extracted_bytes,
            )

            snapshot = {
                "provider": "github",
                "repository": full_name,
                "ref": ref,
                "commit": commit,
                "archiveBytes": archive_bytes,
                "filesExtracted": files_extracted,
            }

            run_id = await self.store.start_run(job, target, snapshot)

            lease_stop = asyncio.Event()
            lease_task = asyncio.create_task(
                self._renew_lease(job.id, self.state.worker_id or "", lease_stop)
            )

            try:
                tools = await run_all(
                    workdir,
                    binaries,
                    reports,
                    timeout=self.settings.tool_timeout_seconds,
                    trivy_cache_dir=Path.home() / ".cache" / "trivy",
                )
            finally:
                lease_stop.set()
                await asyncio.gather(lease_task, return_exceptions=True)

            summaries = [tool.summary() for tool in tools]

            failed = [tool for tool in tools if tool.status != "ok"]
            if failed:
                detail = "; ".join(
                    f"{tool.name}: {tool.error or 'failed'}" for tool in failed
                )
                await self.store.complete_failure(
                    job,
                    run_id,
                    detail,
                    summaries,
                    retryable=False,
                )
                self._record_outcome(False)
                return

            findings = [finding for tool in tools for finding in tool.findings]
            successful_tools = [tool.name for tool in tools]

            await self.store.complete_success(
                job,
                target,
                run_id,
                findings,
                summaries,
                successful_tools,
                stale_after=self.settings.stale_finding_absences,
            )
            self._record_outcome(True)

        logger.info(
            "scan job %s completed: %s findings from %s",
            job.id,
            len(findings),
            ", ".join(successful_tools),
        )

    async def _renew_lease(
        self, job_id: str, worker_id: str, stop: asyncio.Event
    ) -> None:
        if not worker_id:
            return

        interval = max(10.0, self.settings.job_lease_seconds / 3)
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                return
            except TimeoutError:
                pass

            try:
                renewed = await self.store.renew_lease(
                    job_id, worker_id, self.settings.job_lease_seconds
                )
            except Exception as error:  # noqa: BLE001 - keep scanning
                logger.warning("could not renew lease for %s: %s", job_id, error)
                continue

            if not renewed:
                logger.warning("lease for job %s was lost", job_id)
                return

    async def _fail(
        self,
        job: ClaimedJob,
        run_id: str | None,
        message: str,
        *,
        retryable: bool,
    ) -> None:
        try:
            await self.store.complete_failure(
                job, run_id, message, [], retryable=retryable
            )
        except Exception as error:  # noqa: BLE001 - nothing else to do
            logger.error("could not record failure for job %s: %s", job.id, error)
        self._record_outcome(False)

    def _record_outcome(self, success: bool) -> None:
        self.state.last_job_at = datetime.now(UTC)
        self.state.last_job_ok = success

    async def _pause(self, stop: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds)
        except TimeoutError:
            return
