from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from neoshield import __version__
from neoshield.config import get_settings
from neoshield.db.store import ScanStore
from neoshield.worker.bootstrap import ensure_scanners
from neoshield.worker.client import (
    WorkerAuthError,
    WorkerClient,
    WorkerRequestError,
)
from neoshield.worker.jobs import JobRunner
from neoshield.worker.runner import HeartbeatRunner, WorkerState, hostname
from neoshield.worker.scanners import ScannerBinaries

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("neoshield")

client = WorkerClient(
    web_url=settings.web_url,
    token=settings.worker_token,
    timeout=settings.request_timeout_seconds,
)
runner = HeartbeatRunner(client=client, settings=settings, state=WorkerState())

store: ScanStore | None = None
job_runner: JobRunner | None = None
scanners: dict[str, ScannerBinaries] = {
    "binaries": ScannerBinaries(None, None, None)
}


def installed_scanners() -> list[str]:
    return [
        name
        for name, path in scanners["binaries"].items()
        if path is not None
    ]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    global store, job_runner

    stop = asyncio.Event()
    tasks: list[asyncio.Task[None]] = []

    if settings.database_url:
        store = ScanStore(settings.database_url)
        try:
            await store.open()
            logger.info("connected to PostgreSQL for job claiming")
        except Exception as error:  # noqa: BLE001 - health-only mode is valid
            logger.error("database connection failed: %s", error)
            store = None
    else:
        logger.warning(
            "NEOSHIELD_DATABASE_URL is not set: job claiming is disabled"
        )

    async def prepare_scanners() -> None:
        scanners["binaries"] = await ensure_scanners(settings)
        logger.info("scanners ready: %s", installed_scanners() or "none")

    tasks.append(asyncio.create_task(prepare_scanners()))

    if settings.bootstrap_token and settings.workspace_id and not client.has_token:
        try:
            token = await client.register(
                bootstrap_token=settings.bootstrap_token,
                workspace_id=settings.workspace_id,
                name=settings.worker_name,
                version=__version__,
                hostname=hostname(),
            )
            # Keep the token in memory only. Restarting requires either this
            # bootstrap flow again or NEOSHIELD_WORKER_TOKEN set in the env.
            runner.client = WorkerClient(
                web_url=settings.web_url,
                token=token,
                timeout=settings.request_timeout_seconds,
            )
            runner.__post_init__()
            logger.info(
                "worker registered via bootstrap token; set NEOSHIELD_WORKER_TOKEN "
                "in the service environment to survive restarts"
            )
        except (WorkerAuthError, WorkerRequestError) as error:
            logger.error("worker bootstrap registration failed: %s", error)

    if runner.client.has_token:
        tasks.append(asyncio.create_task(runner.run_forever(stop)))
    else:
        logger.warning(
            "starting without NEOSHIELD_WORKER_TOKEN: /health is available but "
            "the worker will not appear online"
        )

    if store is not None and runner.client.has_token:
        job_runner = JobRunner(
            settings=settings,
            store=store,
            state=runner.state,
            scanner_binaries=lambda: scanners["binaries"],
        )
        tasks.append(asyncio.create_task(job_runner.run_forever(stop)))
    elif store is not None:
        logger.warning("job claiming disabled until a worker token is configured")

    try:
        yield
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if store is not None:
            await store.close()


app = FastAPI(
    title="NeoShield worker",
    version=__version__,
    description=(
        "Internal scanning service. Not exposed publicly; authenticated with a "
        "revocable workspace worker token."
    ),
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, object]:
    worker = runner.state.as_dict()
    return {
        "status": "ok",
        "service": "neoshield-python",
        "version": __version__,
        "worker": worker,
        "capabilities": {
            "heartbeat": True,
            "scanners": installed_scanners(),
            "jobClaiming": bool(
                store is not None
                and job_runner is not None
                and runner.state.worker_id
            ),
            "database": store is not None,
        },
    }
