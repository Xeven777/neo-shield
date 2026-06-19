# NeoShield Python service

FastAPI health API plus the background worker that claims scan jobs and runs
Gitleaks, OSV-Scanner and Trivy for repositories, DNS/TLS/HTTP checks for
domains, Wazuh alert normalization for endpoints and authorized Nmap discovery
for network ranges, and read-only AWS configuration checks.

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
- Runs domain checks for assets attached in the UI:
  - DNS: A/AAAA, NS, MX, TXT, SPF, DMARC and CAA;
  - TLS: certificate validation, expiry, negotiated protocol and cipher;
  - HTTP: HTTPS availability, HTTP→HTTPS redirect behaviour and security
    headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options /
    frame-ancestors, Referrer-Policy, Permissions-Policy, Server version).
- Rejects private, loopback, link-local, reserved and shared addresses before
  connecting. Every redirect hop is resolved and checked again; TLS connects to
  the validated address with SNI.
- Writes normalized findings, evidence and stale-resolution events directly to
  Neon in one transaction. Secret values are never read or stored.

Only one scan runs at a time per worker. Every scanner must succeed for a run to
be marked `completed`; the stricter Phase 1 profile fails the run otherwise.

## Phase 2 scope — endpoints and networks

- **Wazuh connector.** Reads alerts from the Wazuh indexer (`_search` on
  `wazuh-alerts-*`, default minimum rule level 5) and, when configured, agent
  inventory/status from the manager API (`/security/user/authenticate`,
  `/agents`). Credentials remain in this service's environment.
- **Normalization.** Selected alert categories become findings
  (authentication, file integrity, malware, vulnerability, agent health,
  configuration, audit); every ingested alert above the threshold is stored as
  a redacted `security_event`. `full_log` and raw payloads are never persisted.
- **Agent mapping.** Wazuh agents are upserted as `endpoint` assets with an
  `endpoint_agent` inventory row, so alerts and findings appear on the
  endpoint asset.
- **Continuous polling.** While a workspace integration is enabled, the poller
  syncs incrementally using `integration.sync_cursor`. Disabling ingestion
  stops polling but keeps history.
- **Nmap discovery.** Two fixed profiles: `discovery` (`-sn -PE -PS22,80,443`)
  and `services` (host discovery plus `-sV --version-light` on an explicit port
  list). Only RFC1918/CGNAT IPv4 ranges up to `/24` (256 addresses); no public
  targets, NSE scripts, OS detection, brute force or exploitation. The worker
  re-validates the exact authorized CIDR stored by the web app.
- **Findings.** One informational finding per discovered host, plus findings
  for risky exposed services (SSH, RDP, databases, Docker API, etc.). Service
  disappearance is only resolved by a complete service-profile run.

The worker does not expose an ingestion HTTP endpoint: it writes directly to
the shared database with the restricted role.

### Wazuh lab

`deploy/lab/wazuh/` contains an automated, pinned `wazuh-docker` single-node
lab with localhost-only ports, an agent enrollment script, an event generator
(failed SSH logins + FIM change) and an exposure check. See its README.

## Phase 4 scope — read-only AWS checks

- **IAM:** users/roles whose attached or inline policies allow a wildcard action
  on all resources. Reported as a least-privilege review item.
- **S3:** missing public-access-block settings, public bucket policies and
  public ACL grants.
- **EC2 security groups:** ingress from `0.0.0.0/0` or `::/0`, with SSH/RDP and
  all-traffic rules called out.
- **CloudTrail:** selected high-signal management events from Event History
  over the configured lookback window (default 24 hours).

Credentials are resolved from Boto3's normal credential chain or
`NEOSHIELD_AWS_PROFILE`. The web app never receives AWS keys. The worker calls
`sts:GetCallerIdentity` and refuses an account whose id does not match the
confirmed asset. No AWS resource is created, changed or deleted. The minimal
IAM policy is in `deploy/aws/read-only-policy.json`.

### Phase 2 settings

| Variable | Purpose |
| --- | --- |
| `NEOSHIELD_WAZUH_ENABLED` | Master switch for indexer polling |
| `NEOSHIELD_WAZUH_INDEXER_URL` / `_USERNAME` / `_PASSWORD` | Indexer API and basic auth (or `_API_TOKEN`) |
| `NEOSHIELD_WAZUH_INDEXER_VERIFY_TLS` / `_CA_PATH` | TLS verification (lab self-signed certs need false or a CA) |
| `NEOSHIELD_WAZUH_INDEX_PATTERN` | Alert index pattern (default `wazuh-alerts-*`) |
| `NEOSHIELD_WAZUH_MIN_LEVEL` | Default minimum Wazuh rule level |
| `NEOSHIELD_WAZUH_POLL_INTERVAL_SECONDS` | Continuous poll cadence |
| `NEOSHIELD_WAZUH_MANAGER_URL` / `_USERNAME` / `_PASSWORD` | Optional manager API for agent inventory |
| `NEOSHIELD_NMAP_PATH` | Optional explicit Nmap binary path |
| `NEOSHIELD_NETWORK_MAX_PREFIX_LENGTH` / `_MAX_HOSTS` | Scope ceiling (`24` / `256`) |
| `NEOSHIELD_NETWORK_PORTS` | Explicit service-detection port list |
| `NEOSHIELD_NETWORK_ALLOW_PUBLIC` | Keep false; public ranges are refused |

Nmap is installed in the container image. Tests cover Wazuh normalization and
Nmap scope/XML/finding logic:

```bash
uv run pytest -q
uv run ruff check src
```

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

### Phase 4 settings

| Variable | Purpose |
| --- | --- |
| `NEOSHIELD_AWS_ENABLED` | Master switch (default `true`); assets still require an explicit confirmation |
| `NEOSHIELD_AWS_PROFILE` | Optional local AWS profile; otherwise the normal credential chain |
| `NEOSHIELD_AWS_MAX_REGIONS` | Maximum regions per asset (default 8) |
| `NEOSHIELD_AWS_MAX_ITEMS` | Per-service item limit to bound scan time |
| `NEOSHIELD_AWS_CLOUDTRAIL_LOOKBACK_HOURS` | Event History lookback (default 24) |
| `NEOSHIELD_AWS_CLOUDTRAIL_MAX_EVENTS` | Maximum high-signal events retained per scan |

Domain checks need no extra binaries. Tuning: `NEOSHIELD_DOMAIN_TIMEOUT_SECONDS`
(default 15), `NEOSHIELD_DOMAIN_MAX_REDIRECTS` (default 5) and
`NEOSHIELD_DOMAIN_CERTIFICATE_WARNING_DAYS` (default 30).

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
  `NEOSHIELD_STALE_FINDING_ABSENCES`). Repository stable keys are tool-scoped;
  domain keys are `domain|dns|…`, `domain|tls|…`, `domain|http|…` and
  `domain|header|…`.
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
