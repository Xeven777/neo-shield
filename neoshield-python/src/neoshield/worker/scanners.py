"""Scanner adapters.

Each adapter runs a pinned binary as a subprocess with a timeout and parses its
JSON report into normalized findings. Repository code is never executed; the
scanners only read files.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from neoshield.worker.normalize import (
    Finding,
    parse_gitleaks,
    parse_osv,
    parse_trivy,
)

logger = logging.getLogger(__name__)

MAX_REPORT_BYTES = 25 * 1024 * 1024

ToolStatus = Literal["ok", "missing", "error"]


@dataclass(slots=True)
class ToolRun:
    name: str
    version: str | None
    status: ToolStatus
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0

    def summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "findingCount": len(self.findings),
            "error": self.error,
            "durationMs": self.duration_ms,
        }


@dataclass(frozen=True, slots=True)
class ScannerBinaries:
    gitleaks: Path | None
    osv_scanner: Path | None
    trivy: Path | None

    def items(self) -> list[tuple[str, Path | None]]:
        return [
            ("gitleaks", self.gitleaks),
            ("osv-scanner", self.osv_scanner),
            ("trivy", self.trivy),
        ]


def _decode(value: bytes | None) -> str:
    if not value:
        return ""
    return value.decode("utf-8", "replace").replace("\x00", "")[:500]


async def _run_command(
    command: list[str],
    *,
    timeout: int,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        start_new_session=True,
    )

    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:  # pragma: no cover - already exited
            pass
        await process.wait()
        raise TimeoutError(f"scanner timed out after {timeout}s") from None

    return process.returncode or 0, _decode(stderr)


async def tool_version(binary: Path, arguments: list[str]) -> str | None:
    try:
        process = await asyncio.create_subprocess_exec(
            str(binary),
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15)
    except (OSError, TimeoutError):
        return None

    text = _decode(stdout).strip().splitlines()
    return text[0][:120] if text else None


def _read_report(path: Path) -> object:
    if not path.exists():
        return None
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("scanner report exceeded the size limit")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


async def run_gitleaks(
    binary: Path, workdir: Path, report: Path, timeout: int
) -> ToolRun:
    version = await tool_version(binary, ["version"])
    started = asyncio.get_running_loop().time()

    command = [
        str(binary),
        "detect",
        "--source",
        str(workdir),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
        "--no-banner",
        "--no-git",
        "--redact",
        "--log-level",
        "error",
    ]

    try:
        code, stderr = await _run_command(command, timeout=timeout)
    except (OSError, TimeoutError) as error:
        return ToolRun(
            name="gitleaks",
            version=version,
            status="error",
            error=str(error),
            duration_ms=int((asyncio.get_running_loop().time() - started) * 1000),
        )

    duration = int((asyncio.get_running_loop().time() - started) * 1000)

    if code != 0:
        return ToolRun(
            name="gitleaks",
            version=version,
            status="error",
            error=f"gitleaks exited with code {code}: {stderr}"[:300],
            duration_ms=duration,
        )

    try:
        findings = parse_gitleaks(_read_report(report))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return ToolRun(
            name="gitleaks",
            version=version,
            status="error",
            error=f"gitleaks report could not be parsed: {error}"[:300],
            duration_ms=duration,
        )

    return ToolRun(
        name="gitleaks",
        version=version,
        status="ok",
        findings=findings,
        duration_ms=duration,
    )


async def run_osv_scanner(
    binary: Path, workdir: Path, report: Path, timeout: int
) -> ToolRun:
    version = await tool_version(binary, ["--version"])
    started = asyncio.get_running_loop().time()

    command = [
        str(binary),
        "--format",
        "json",
        "--output",
        str(report),
        "--recursive",
        str(workdir),
    ]

    try:
        code, stderr = await _run_command(command, timeout=timeout)
    except (OSError, TimeoutError) as error:
        return ToolRun(
            name="osv-scanner",
            version=version,
            status="error",
            error=str(error),
            duration_ms=int((asyncio.get_running_loop().time() - started) * 1000),
        )

    duration = int((asyncio.get_running_loop().time() - started) * 1000)

    # v1 exits 1 when vulnerabilities are found; that is still a successful scan.
    if code not in (0, 1):
        return ToolRun(
            name="osv-scanner",
            version=version,
            status="error",
            error=f"osv-scanner exited with code {code}: {stderr}"[:300],
            duration_ms=duration,
        )

    try:
        findings = parse_osv(_read_report(report))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return ToolRun(
            name="osv-scanner",
            version=version,
            status="error",
            error=f"osv-scanner report could not be parsed: {error}"[:300],
            duration_ms=duration,
        )

    return ToolRun(
        name="osv-scanner",
        version=version,
        status="ok",
        findings=findings,
        duration_ms=duration,
    )


async def run_trivy(
    binary: Path,
    workdir: Path,
    report: Path,
    timeout: int,
    cache_dir: Path | None = None,
) -> ToolRun:
    version = await tool_version(binary, ["--version"])
    started = asyncio.get_running_loop().time()

    command = [
        str(binary),
        "fs",
        "--format",
        "json",
        "--output",
        str(report),
        "--scanners",
        "vuln,misconfig",
        "--skip-version-check",
        "--no-progress",
        "--quiet",
        str(workdir),
    ]

    environment = dict(os.environ)
    if cache_dir is not None:
        environment["TRIVY_CACHE_DIR"] = str(cache_dir)

    try:
        code, stderr = await _run_command(
            command, timeout=timeout, env=environment
        )
    except (OSError, TimeoutError) as error:
        return ToolRun(
            name="trivy",
            version=version,
            status="error",
            error=str(error),
            duration_ms=int((asyncio.get_running_loop().time() - started) * 1000),
        )

    duration = int((asyncio.get_running_loop().time() - started) * 1000)

    if code != 0:
        return ToolRun(
            name="trivy",
            version=version,
            status="error",
            error=f"trivy exited with code {code}: {stderr}"[:300],
            duration_ms=duration,
        )

    try:
        findings = parse_trivy(_read_report(report))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return ToolRun(
            name="trivy",
            version=version,
            status="error",
            error=f"trivy report could not be parsed: {error}"[:300],
            duration_ms=duration,
        )

    return ToolRun(
        name="trivy",
        version=version,
        status="ok",
        findings=findings,
        duration_ms=duration,
    )


async def run_all(
    workdir: Path,
    binaries: ScannerBinaries,
    reports_dir: Path,
    *,
    timeout: int,
    trivy_cache_dir: Path | None = None,
) -> list[ToolRun]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    results: list[ToolRun] = []

    if binaries.gitleaks is None:
        results.append(
            ToolRun(
                name="gitleaks",
                version=None,
                status="missing",
                error="gitleaks binary is not installed",
            )
        )
    else:
        results.append(
            await run_gitleaks(
                binaries.gitleaks, workdir, reports_dir / "gitleaks.json", timeout
            )
        )

    if binaries.osv_scanner is None:
        results.append(
            ToolRun(
                name="osv-scanner",
                version=None,
                status="missing",
                error="osv-scanner binary is not installed",
            )
        )
    else:
        results.append(
            await run_osv_scanner(
                binaries.osv_scanner, workdir, reports_dir / "osv.json", timeout
            )
        )

    if binaries.trivy is None:
        results.append(
            ToolRun(
                name="trivy",
                version=None,
                status="missing",
                error="trivy binary is not installed",
            )
        )
    else:
        results.append(
            await run_trivy(
                binaries.trivy,
                workdir,
                reports_dir / "trivy.json",
                timeout,
                trivy_cache_dir,
            )
        )

    return results
