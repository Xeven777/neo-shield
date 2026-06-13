# NeoShield Python service

FastAPI health API plus the background worker that claims scan jobs and runs
Gitleaks, OSV-Scanner and Trivy. Later phases add Nmap, Wazuh and AWS checks.

This is a **separate application** from the Next.js web app. It has its own
dependencies (`uv`), image and release lifecycle. It never owns the database
schema — Drizzle in the web app is the only migration authority.

## Phase 1 scope

- `GET /health` reports service, worker and scanner state (no secrets).
- Heartbeat loop posts to the web app's internal worker API every 30 seconds.
- Claims `scan_job` rows directly from Neon with
  `FOR UPDATE SKIP LOCKED`, leases and retries.
- Downloads the exact commit tarball from GitHub with a short-lived installation
  token, extracts it with a hostile-archive-safe filter, and runs:
  - Gitleaks for secrets;
  - OSV-Scanner for dependency vulnerabilities;
  - Trivy for vulnerabilities and configuration misconfigurations.
- Writes normalized findings, evidence and stale-resolution events directly to
  Neon in one transaction. Secret values are never read or stored.

Only one scan runs at a time per worker. Every scanner must succeed for a run to
be marked `completed`; the stricter Phase 1 profile fails the run otherwise.

## Run locally

```bash
uv sync
cp .env.example .env       # set web URL, worker token, database URL, GitHub App
uv run uvicorn neoshield.api.main:app --reload --port 8000
curl -s localhost:8000/health | jq
```

Tests:

```bash
uv run pytest -q
uv run ruff check .
```

## Getting a worker token

1. Sign in to the web app.
2. Settings → Worker tokens → New worker.
3. Copy the `nsw_…` token immediately (it is stored only as a SHA-256 hash).
4. Put it in `NEOSHIELD_WORKER_TOKEN` and restart this service.
5. The worker appears online within 30 seconds; the web UI treats it as offline
   if it has not been seen for 90 seconds.

`NEOSHIELD_HEARTBEAT_INTERVAL_SECONDS` is the local retry cadence. The web app
returns the authoritative interval with every heartbeat response.

## Required settings for scanning

| Variable | Purpose |
| --- | --- |
| `NEOSHIELD_DATABASE_URL` | Restricted Neon role for claiming and result writes |
| `NEOSHIELD_GITHUB_APP_ID` | GitHub App id (same app as the web UI) |
| `NEOSHIELD_GITHUB_APP_PRIVATE_KEY` | PEM key; escaped `\n` accepted |
| `NEOSHIELD_SCANNER_DIR` | Writable binary directory (default `/opt/neoshield/scanners`) |
| `NEOSHIELD_SCANNER_AUTO_INSTALL` | Download pinned binaries on startup (default true) |

Pinned scanners: Gitleaks 8.21.2, OSV-Scanner 1.9.2, Trivy 0.76.2. Downloads
happen on first startup and are checksum-verified where the project publishes a
checksum file. If a binary cannot be installed, `/health` lists only the others
and scans fail with a clear error instead of silently skipping coverage.

Safety limits (chosen stricter for Phase 1): 50 MB tarball, 5,000 files, 5 MB
per file, 200 MB extracted, 180 seconds per scanner, lease 600 seconds. Trivy
downloads its vulnerability database on first use, which needs network access and
may take longer than a single 180-second scan window; pre-warm it in the image or
before demos if that matters.

## Queue contract

- Claiming is transactional: expired leases over `max_attempts` are failed, then
  one `queued` (or expired-lease) job is selected with
  `FOR UPDATE SKIP LOCKED` and marked `leased`.
- `attempts` increments on claim; transient GitHub/DB failures requeue with
  backoff, scanner failures are terminal.
- Findings are upserted on `(asset_id, stable_key)`; evidence is one row per
  finding. A finding absent from two consecutive successful scans is resolved
  with a `finding_status_event` (threshold configurable via
  `NEOSHIELD_STALE_FINDING_ABSENCES`).
- The worker role must not be able to write Better Auth tables.

## Contracts

`POST {NEOSHIELD_WEB_URL}/api/internal/worker/heartbeat`

```http
Authorization: Bearer nsw_...
Content-Type: application/json

{ "version": "0.1.0", "hostname": "lab-worker" }
```

```json
{
  "data": {
    "workerId": "uuid",
    "workspaceId": "uuid",
    "name": "scan-worker-1",
    "scopes": ["worker:heartbeat"],
    "heartbeatIntervalSeconds": 30
  }
}
```

`POST /api/internal/workers/register` (bootstrap only) accepts
`{ workspaceId, name, version, hostname }` with the deployment bootstrap token
and returns a new worker token once.

## Result ingestion decision

Results are written **directly to Neon** by the worker using a restricted
PostgreSQL role. The web app does not expose a second, parallel ingestion
endpoint. See `../web/docs/architecture.md` for the full rationale.
