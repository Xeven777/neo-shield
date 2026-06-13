"""Background Wazuh poller.

The web app only records which workspace/project should receive endpoint
telemetry. This loop reads that intent from `integration`, pulls alerts from
the worker's configured Wazuh instance, maps agents to endpoint assets and
writes security events plus normalized findings.

Polling is incremental: each integration row stores a `sync_cursor` timestamp.
Repeated alert ids are deduplicated by `security_event`, so a `>=` overlap is
safe across restarts and clock skew.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from neoshield.config import Settings
from neoshield.db.store import (
    ScanStore,
    WazuhIngestResult,
    WazuhIntegration,
)
from neoshield.worker.runner import WorkerState
from neoshield.worker.wazuh_client import (
    WazuhAuthError,
    WazuhClient,
    WazuhError,
)
from neoshield.worker.wazuh_normalize import (
    AgentInfo,
    normalize_agent,
    normalize_alert,
)

logger = logging.getLogger(__name__)


@dataclass
class WazuhPoller:
    settings: Settings
    store: ScanStore
    state: WorkerState
    client_factory: Callable[[Settings], WazuhClient] = WazuhClient

    async def run_forever(self, stop: asyncio.Event) -> None:
        logger.info(
            "Wazuh poller starting: interval=%ss",
            self.settings.wazuh_poll_interval_seconds,
        )
        while not stop.is_set():
            try:
                await self.tick()
            except Exception as error:  # noqa: BLE001 - keep the loop alive
                logger.warning("Wazuh poll failed: %s", error)
                self.state.wazuh_last_error = str(error)[:300]

            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=float(self.settings.wazuh_poll_interval_seconds),
                )
            except TimeoutError:
                continue

        logger.info("Wazuh poller stopped")

    async def tick(self) -> None:
        if not self.settings.wazuh_configured:
            return

        integrations = await self.store.list_wazuh_integrations(
            default_min_level=self.settings.wazuh_min_level
        )
        if not integrations:
            return

        client = self.client_factory(self.settings)
        agents: list[AgentInfo] | None = None
        manager_error: str | None = None

        try:
            if client.manager_configured:
                try:
                    raw_agents = await client.list_agents()
                    agents = [
                        normalized
                        for normalized in (
                            normalize_agent(entry) for entry in raw_agents
                        )
                        if normalized is not None
                    ]
                except WazuhError as error:
                    manager_error = str(error)[:300]
                    logger.warning("Wazuh manager inventory failed: %s", error)

            for integration in integrations:
                await self._poll_integration(
                    client,
                    integration,
                    agents=agents,
                    manager_error=manager_error,
                )
        finally:
            await client.aclose()

    async def _poll_integration(
        self,
        client: WazuhClient,
        integration: WazuhIntegration,
        *,
        agents: list[AgentInfo] | None,
        manager_error: str | None,
    ) -> None:
        result: WazuhIngestResult | None = None
        agent_count = int(
            integration.metadata.get("endpointsTracked", 0)
            if isinstance(integration.metadata.get("endpointsTracked"), int)
            else 0
        )

        try:
            if agents is not None:
                agent_sync = await self.store.sync_wazuh_agents(
                    integration, agents
                )
                agent_count = agent_sync.agents

            now = datetime.now(UTC)
            after = integration.cursor or (
                now
                - timedelta(
                    minutes=self.settings.wazuh_initial_lookback_minutes
                )
            )
            hits = await client.search_alerts(
                after=after,
                min_level=integration.min_level,
                size=self.settings.wazuh_max_alerts_per_poll,
            )
            alerts = [
                alert
                for alert in (
                    normalize_alert(hit, min_level=integration.min_level)
                    for hit in hits
                )
                if alert is not None
            ]
            result = await self.store.ingest_wazuh_alerts(integration, alerts)

            cursor = (
                max(alert.event_time for alert in alerts)
                if alerts
                else datetime.now(UTC)
            )
            metadata = integration.metadata
            patch: dict[str, object] = {
                "endpointsTracked": agent_count,
                "alertsIngested": int(metadata.get("alertsIngested", 0) or 0)
                + result.events,
                "findingsIngested": int(
                    metadata.get("findingsIngested", 0) or 0
                )
                + result.findings,
                "lastBatchEvents": result.events,
                "lastBatchFindings": result.findings,
                "lastBatchDuplicates": result.duplicates,
            }
            if alerts:
                patch["lastAlertAt"] = cursor.isoformat()
            if manager_error:
                patch["managerError"] = manager_error

            await self.store.save_wazuh_integration_state(
                integration.id,
                status="connected",
                cursor_time=cursor,
                last_error=None,
                synced=True,
                metadata_patch=patch,
            )

            self.state.wazuh_last_sync_at = datetime.now(UTC)
            self.state.wazuh_last_error = None
            self.state.wazuh_alerts_ingested += result.events

            logger.info(
                "Wazuh sync %s: %s fetched, %s event(s), %s finding(s), "
                "%s duplicate(s)",
                integration.id,
                len(hits),
                result.events,
                result.findings,
                result.duplicates,
            )
        except WazuhAuthError as error:
            logger.error("Wazuh credentials rejected: %s", error)
            self.state.wazuh_last_error = str(error)[:300]
            await self.store.save_wazuh_integration_state(
                integration.id,
                status="error",
                last_error=str(error),
                metadata_patch={"managerError": manager_error}
                if manager_error
                else None,
            )
        except WazuhError as error:
            logger.warning(
                "Wazuh sync failed for %s: %s", integration.id, error
            )
            self.state.wazuh_last_error = str(error)[:300]
            await self.store.save_wazuh_integration_state(
                integration.id,
                status="error",
                last_error=str(error),
                metadata_patch=(
                    {"managerError": manager_error} if manager_error else None
                ),
            )
