from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from neoshield import __version__
from neoshield.config import Settings
from neoshield.worker.client import (
    WorkerAuthError,
    WorkerClient,
    WorkerRequestError,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class WorkerState:
    """Non-secret worker state exposed through /health."""

    configured: bool = False
    registered: bool = False
    worker_id: str | None = None
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    interval_seconds: int = 30
    last_job_at: datetime | None = None
    last_job_ok: bool | None = None

    def is_online(self, now: datetime | None = None) -> bool:
        if self.last_success_at is None:
            return False
        current = now or _utcnow()
        return (current - self.last_success_at).total_seconds() <= (
            self.interval_seconds * 3
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "configured": self.configured,
            "registered": self.registered,
            "workerId": self.worker_id,
            "online": self.is_online(),
            "lastHeartbeatAt": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "lastAttemptAt": (
                self.last_attempt_at.isoformat() if self.last_attempt_at else None
            ),
            "lastError": self.last_error,
            "consecutiveFailures": self.consecutive_failures,
            "heartbeatIntervalSeconds": self.interval_seconds,
            "lastJobAt": (
                self.last_job_at.isoformat() if self.last_job_at else None
            ),
            "lastJobOk": self.last_job_ok,
        }


@dataclass
class HeartbeatRunner:
    client: WorkerClient
    settings: Settings
    state: WorkerState = field(default_factory=WorkerState)

    def __post_init__(self) -> None:
        self.state.configured = self.client.has_token
        self.state.interval_seconds = self.settings.heartbeat_interval_seconds

    async def tick(self) -> None:
        if not self.client.has_token:
            self.state.last_error = "NEOSHIELD_WORKER_TOKEN is not set"
            return

        self.state.last_attempt_at = _utcnow()
        try:
            heartbeat = await self.client.heartbeat(
                version=__version__,
                hostname=hostname(),
            )
        except WorkerAuthError as error:
            # Retrying a revoked token cannot succeed; surface it clearly.
            self.state.registered = False
            self.state.consecutive_failures += 1
            self.state.last_error = str(error)
            logger.error(
                "worker token rejected: create a new token in NeoShield settings"
            )
            return
        except (httpx.HTTPError, WorkerRequestError) as error:
            self.state.consecutive_failures += 1
            self.state.last_error = str(error)
            logger.warning("heartbeat failed: %s", error)
            return

        self.state.registered = True
        self.state.worker_id = heartbeat.worker_id
        self.state.last_success_at = _utcnow()
        self.state.last_error = None
        self.state.consecutive_failures = 0
        self.state.interval_seconds = heartbeat.interval_seconds

    async def run_forever(self, stop: asyncio.Event) -> None:
        logger.info(
            "worker starting: interval=%ss web=%s",
            self.settings.heartbeat_interval_seconds,
            self.settings.web_url,
        )
        while not stop.is_set():
            await self.tick()

            if self.state.consecutive_failures == 0:
                delay = float(self.state.interval_seconds)
            else:
                # Bounded exponential backoff, capped at one minute.
                backoff_step = min(self.state.consecutive_failures - 1, 3)
                delay = min(60.0, 5.0 * 2**backoff_step)

            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                continue

        logger.info("worker stopped")


def hostname() -> str:
    return socket.gethostname()[:200]
