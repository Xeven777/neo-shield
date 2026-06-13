"""Scan job execution.

One job at a time per worker: claim, fetch a tarball snapshot, run the scanners
and write normalized findings. Long scans renew the lease; results are written
in one transaction so a crash never leaves a half-ingested run.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from neoshield.config import Settings
from neoshield.db.store import AssetTarget, ClaimedJob, ScanStore, StoreError
from neoshield.worker.domain import DomainBlockedError, DomainCheckError, check_domain
from neoshield.worker.github_client import (
    GithubError,
    download_tarball,
    installation_token,
    resolve_commit,
    safe_extract,
)
from neoshield.worker.network_scan import (
    NetworkScanError,
    NetworkScopeError,
    scan_network,
    validate_scope,
)
from neoshield.worker.normalize import Finding, clip
from neoshield.worker.runner import WorkerState
from neoshield.worker.scanners import ScannerBinaries, run_all
from neoshield.worker.wazuh_client import (
    WazuhAuthError,
    WazuhClient,
    WazuhError,
)
from neoshield.worker.wazuh_normalize import normalize_agent, normalize_alert

logger = logging.getLogger(__name__)

# A domain run is complete only when all three check groups produced a result.
DOMAIN_TOOLS = ["dns", "tls", "http"]


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

        if target.asset_type == "repository":
            await self._execute_repository(job, target, worker_id)
        elif target.asset_type == "domain":
            await self._execute_domain(job, target, worker_id)
        elif target.asset_type == "endpoint":
            await self._execute_endpoint(job, target, worker_id)
        elif target.asset_type == "network":
            await self._execute_network(job, target, worker_id)
        else:
            await self._fail(
                job,
                None,
                "Unsupported asset type for this worker",
                retryable=False,
            )

    async def _execute_repository(
        self, job: ClaimedJob, target: AssetTarget, worker_id: str
    ) -> None:
        if not target.identifier.startswith("github:"):
            await self._fail(
                job,
                None,
                "Unsupported repository asset for this worker",
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

    async def _execute_domain(
        self, job: ClaimedJob, target: AssetTarget, worker_id: str
    ) -> None:
        domain = target.config.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            await self._fail(
                job, None, "Domain asset metadata is incomplete", retryable=False
            )
            return

        await self.store.mark_running(
            job.id, worker_id, self.settings.job_lease_seconds
        )

        findings: list[Finding] = []
        snapshot: dict[str, object] = {}
        error: Exception | None = None

        lease_stop = asyncio.Event()
        lease_task = asyncio.create_task(
            self._renew_lease(job.id, worker_id, lease_stop)
        )
        try:
            findings, snapshot = await check_domain(domain.strip(), self.settings)
        except Exception as caught:  # noqa: BLE001 - classified below
            error = caught
        finally:
            lease_stop.set()
            await asyncio.gather(lease_task, return_exceptions=True)

        if isinstance(error, DomainBlockedError):
            # A private/reserved answer is a policy refusal, not a transient fault.
            await self._fail(job, None, str(error), retryable=False)
            return

        if error is not None:
            if not isinstance(error, DomainCheckError):
                logger.exception(
                    "domain scan job %s failed unexpectedly", job.id, exc_info=error
                )
            await self._fail(job, None, str(error), retryable=True)
            return

        run_id = await self.store.start_run(job, target, snapshot, scanner="domain")

        counts = Counter(finding.source_tool for finding in findings)
        summaries = [
            {
                "name": tool,
                "version": None,
                "status": "ok",
                "findingCount": counts.get(tool, 0),
                "error": None,
            }
            for tool in DOMAIN_TOOLS
        ]

        try:
            await self.store.complete_success(
                job,
                target,
                run_id,
                findings,
                summaries,
                DOMAIN_TOOLS,
                stale_after=self.settings.stale_finding_absences,
            )
        except StoreError as error:
            # Keep the run row truthful; the job becomes retryable again.
            await self._fail(job, run_id, str(error), retryable=True)
            return

        self._record_outcome(True)

        logger.info(
            "domain scan job %s completed: %s findings for %s",
            job.id,
            len(findings),
            domain,
        )

    async def _execute_endpoint(
        self, job: ClaimedJob, target: AssetTarget, worker_id: str
    ) -> None:
        agent_id = target.config.get("agentId")
        if not isinstance(agent_id, str) or not agent_id:
            if target.identifier.startswith("wazuh:"):
                agent_id = target.identifier.split(":", 1)[1]
            else:
                await self._fail(
                    job,
                    None,
                    "Endpoint asset is missing its Wazuh agent id",
                    retryable=False,
                )
                return

        if not self.settings.wazuh_configured:
            await self._fail(
                job,
                None,
                "Wazuh is not configured on this worker "
                "(NEOSHIELD_WAZUH_ENABLED / indexer URL and credentials)",
                retryable=False,
            )
            return

        integration = await self.store.get_wazuh_integration_for_workspace(
            target.workspace_id,
            default_min_level=self.settings.wazuh_min_level,
        )
        if integration is None:
            await self._fail(
                job,
                None,
                "Wazuh ingestion is not enabled for this workspace",
                retryable=False,
            )
            return

        await self.store.mark_running(
            job.id, worker_id, self.settings.job_lease_seconds
        )

        lookback = datetime.now(UTC) - timedelta(
            hours=self.settings.wazuh_endpoint_lookback_hours
        )
        latest = await self.store.latest_security_event_time(target.asset_id)
        after = max(lookback, latest) if latest is not None else lookback

        snapshot: dict[str, object] = {
            "provider": "wazuh",
            "agentId": agent_id,
            "agentName": target.display_name,
            "windowStart": after.isoformat(),
        }
        run_id = await self.store.start_run(
            job, target, snapshot, scanner="endpoint"
        )

        lease_stop = asyncio.Event()
        lease_task = asyncio.create_task(
            self._renew_lease(job.id, worker_id, lease_stop)
        )
        client = WazuhClient(self.settings)
        result = None
        hits_count = 0
        agent_state: str | None = None

        try:
            if client.manager_configured:
                raw_agents = await client.list_agents()
                agents = [
                    normalized
                    for normalized in (
                        normalize_agent(entry) for entry in raw_agents
                    )
                    if normalized is not None
                ]
                selected = [
                    agent for agent in agents if agent.agent_id == agent_id
                ]
                if selected:
                    agent_state = selected[0].status
                    await self.store.sync_wazuh_agents(
                        integration, selected
                    )

            hits = await client.search_alerts(
                after=after,
                min_level=integration.min_level,
                size=self.settings.wazuh_max_alerts_per_poll,
                agent_id=agent_id,
            )
            hits_count = len(hits)
            alerts = [
                alert
                for alert in (
                    normalize_alert(hit, min_level=integration.min_level)
                    for hit in hits
                )
                if alert is not None
            ]
            result = await self.store.ingest_wazuh_alerts(
                integration, alerts, run_id=run_id
            )
        except WazuhAuthError as error:
            await self._fail(job, run_id, str(error), retryable=False)
            return
        except WazuhError as error:
            await self._fail(job, run_id, str(error), retryable=True)
            return
        finally:
            lease_stop.set()
            await asyncio.gather(lease_task, return_exceptions=True)
            await client.aclose()

        if result is None:
            await self._fail(
                job, run_id, "Wazuh collection returned no result", retryable=True
            )
            return

        snapshot.update(
            {
                "alertsFetched": hits_count,
                "eventsIngested": result.events,
                "findingsObserved": result.findings,
                "duplicates": result.duplicates,
                "agentState": agent_state,
            }
        )
        tools = [
            {
                "name": "wazuh",
                "version": None,
                "status": "ok",
                "findingCount": result.findings,
                "error": None,
            }
        ]

        try:
            await self.store.complete_ingest_run(
                job,
                run_id,
                tools=tools,
                finding_count=result.findings,
                snapshot=snapshot,
            )
        except StoreError as error:
            await self._fail(job, run_id, str(error), retryable=True)
            return

        self._record_outcome(True)
        logger.info(
            "endpoint scan job %s completed: %s alert(s), %s event(s), "
            "%s finding(s) for agent %s",
            job.id,
            hits_count,
            result.events,
            result.findings,
            agent_id,
        )

    async def _execute_network(
        self, job: ClaimedJob, target: AssetTarget, worker_id: str
    ) -> None:
        cidr = target.config.get("cidr")
        profile = target.config.get("scanProfile") or "services"
        authorization = target.config.get("authorization")

        if not isinstance(cidr, str) or not cidr.strip():
            await self._fail(
                job, None, "Network asset is missing its CIDR range", retryable=False
            )
            return

        if profile not in {"discovery", "services"}:
            await self._fail(
                job, None, "Unsupported network scan profile", retryable=False
            )
            return

        if not isinstance(authorization, dict):
            await self._fail(
                job,
                None,
                "Network asset has no recorded authorization",
                retryable=False,
            )
            return

        confirmed_by = authorization.get("confirmedByUserId")
        confirmed_at = authorization.get("confirmedAt")
        authorized_scope = authorization.get("scope")
        if not confirmed_by or not confirmed_at or not authorized_scope:
            await self._fail(
                job,
                None,
                "Network asset authorization record is incomplete",
                retryable=False,
            )
            return

        try:
            network = validate_scope(cidr, self.settings)
        except NetworkScopeError as error:
            await self._fail(job, None, str(error), retryable=False)
            return

        if str(network) != cidr.strip() or str(network) != authorized_scope:
            await self._fail(
                job,
                None,
                "Scan scope does not match the authorized CIDR",
                retryable=False,
            )
            return

        await self.store.mark_running(
            job.id, worker_id, self.settings.job_lease_seconds
        )

        lease_stop = asyncio.Event()
        lease_task = asyncio.create_task(
            self._renew_lease(job.id, worker_id, lease_stop)
        )
        outcome = None
        error: Exception | None = None
        try:
            outcome = await scan_network(cidr.strip(), str(profile), self.settings)
        except Exception as caught:  # noqa: BLE001 - classified below
            error = caught
        finally:
            lease_stop.set()
            await asyncio.gather(lease_task, return_exceptions=True)

        if isinstance(error, NetworkScopeError):
            await self._fail(job, None, str(error), retryable=False)
            return
        if isinstance(error, NetworkScanError):
            retryable = "not installed" not in str(error)
            await self._fail(job, None, str(error), retryable=retryable)
            return
        if error is not None:
            logger.exception(
                "network scan job %s failed unexpectedly", job.id, exc_info=error
            )
            await self._fail(job, None, clip(error, 300), retryable=True)
            return

        if outcome is None:
            await self._fail(
                job, None, "Network scan returned no result", retryable=True
            )
            return

        run_id = await self.store.start_run(
            job, target, outcome.snapshot, scanner="network"
        )
        tools = [
            {
                "name": "nmap",
                "version": outcome.snapshot.get("nmapVersion"),
                "status": "ok",
                "findingCount": len(outcome.findings),
                "error": None,
            }
        ]

        try:
            await self.store.complete_network_success(
                job,
                target,
                run_id,
                outcome,
                tools,
                stale_after=self.settings.stale_finding_absences,
            )
        except StoreError as caught:
            await self._fail(job, run_id, str(caught), retryable=True)
            return

        self._record_outcome(True)
        logger.info(
            "network scan job %s completed: %s host(s), %s finding(s) for %s",
            job.id,
            len(outcome.hosts),
            len(outcome.findings),
            cidr,
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
