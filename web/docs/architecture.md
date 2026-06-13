# NeoShield web — architecture decisions (Phase 0)

## Applications and repositories

- `web/` (this app): Next.js App Router, TypeScript, Better Auth, Drizzle, Neon.
- `../neoshield-python/`: FastAPI + worker, separate dependencies and image.
- `../deploy/`: Compose deployment for both images. No database container.
- Nothing is a monorepo: no shared package manager, no workspace spanning the two
  applications.

## Schema ownership

Drizzle is the only migration authority. `lib/db/schema.ts` is the source of
truth; `drizzle/` holds generated SQL. The Python service reads/writes the tables
it needs with parameterized SQL and must never migrate or alter the schema.

Physical identifiers are snake_case (`snakeCase.table`); TypeScript keys stay
camelCase so the Better Auth Drizzle adapter maps model fields directly.

## Authentication and authorization

- Better Auth owns users, sessions, accounts and verifications.
- Methods: email OTP, email magic link, Google OAuth. OTPs are stored hashed.
- Cookies: Better Auth defaults plus `useSecureCookies` in production; HttpOnly
  and SameSite=Lax are set by Better Auth.
- Every server action and route handler resolves the session server-side, then
  the active workspace, then the caller's role. Ownership never comes from the
  request body or URL.
- Phase 0 is single-workspace: the user's oldest membership is active. This is a
  lookup rule, not an authorization shortcut — queries are still scoped by
  `workspace_id`.
- Mutations require `owner` or `admin`.

## Worker identity

- A worker token is generated in the UI, shown once, and stored only as
  SHA-256 (plus a short non-secret prefix for identification).
- Tokens are workspace-scoped and revocable. Revocation is immediate because the
  lookup filters on `status = 'active'`.
- The Python service authenticates with `Authorization: Bearer nsw_…`; it never
  receives browser cookies.
- Optional bootstrap registration uses a deployment-level
  `WORKER_BOOTSTRAP_TOKEN` and is meant for first boot. Prefer a pre-issued token
  in `NEOSHIELD_WORKER_TOKEN` so restarts do not need the bootstrap credential.

## Result ingestion: direct database writes (decided)

Scenario 5.6 allows either direct DB writes or a Next.js ingestion endpoint.
**Phase 0 chooses direct DB writes by the Python worker** using a restricted
PostgreSQL role.

Reasons:

- one write path, no split-brain result status;
- no large scanner payloads through the web tier;
- the worker already needs read access to `scan_job` to claim work;
- Next.js stays responsible for user-facing authorization and mutations.

The web app therefore only exposes the small internal worker API for identity
and heartbeat, not for results. The Python role must be limited to the tables it
needs (`scan_job`, `worker`, findings/evidence once added) and must not be able
to write Better Auth tables.

## Queue contract

`scan_job` is the queue. Phase 0 defines the structure only:

- `idempotency_key` (unique), `status` (`queued`, `leased`, `running`,
  `completed`, `failed`, `cancelled`), `attempts` / `max_attempts`,
  `available_at`, `lease_expires_at`, `leased_by_worker_id`,
  `started_at`, `completed_at`, `error_summary`.
- Claiming will use `SELECT … FOR UPDATE SKIP LOCKED` plus a lease update inside
  one transaction, so two workers cannot claim the same job.
- Longer scans will renew the lease with a heartbeat; expired leases become
  claimable again.

No Redis, Kafka or external broker is used.

## Phase 1: repository and domain scanning (implemented)

Two asset types are scannable: GitHub repositories (Gitleaks, OSV-Scanner,
Trivy) and domains (DNS, TLS, redirects, security headers). Both write into the
same normalized finding model and scan history.

### GitHub access

- One GitHub App installation per workspace. App ID, slug and private key are
  server-only env vars; installation tokens are minted on demand and cached in
  process memory only.
- The install flow uses an HMAC-signed state (workspace id, user id, 10-minute
  expiry) and verifies the session, workspace membership and admin role on the
  callback before storing anything.
- Only repositories granted to the installation are listed. Attaching one
  creates a `repository` asset whose identifier is `github:<owner>/<name>`.
- GitHub sign-in and GitHub repository access are separate credentials. User
  sign-in uses the same App's OAuth client id/secret through Better Auth
  (`/api/auth/callback/github`) when `GITHUB_APP_CLIENT_ID`/`GITHUB_APP_CLIENT_SECRET`
  are set; it grants no repository permission and is independent of App
  installation access.

### Domain checks

- A domain is an `asset` row of type `domain` with identifier `domain:<host>`
  and config `{ provider: "domain", domain, url }`. It is attached to a project
  from Integrations; no provider credential is required.
- The worker only reads public DNS and HTTPS. It resolves the target first and
  refuses private, loopback, link-local, reserved and shared addresses, then
  repeats that check for every redirect hop. TLS connects to the validated
  address with SNI, so a second DNS answer cannot move the connection.
- DNS: A/AAAA, NS, MX, TXT, SPF, DMARC and CAA. TLS: certificate validation,
  expiry, protocol and cipher. HTTP: HTTPS availability, HTTP→HTTPS redirect
  behaviour and security headers.
- Stable keys are deterministic per check (`domain|dns|…`, `domain|tls|…`,
  `domain|http|…`, `domain|header|…`), so fixed issues resolve on a later
  successful run and regressions re-open the finding.
- A domain run is recorded with `scan_run.scanner = 'domain'` and tool summaries
  `dns`, `tls` and `http`, which the Scans page and finding provenance display.

### Worker data path

The worker talks to Neon directly with psycopg 3 (async pool), as decided in
Phase 0. It never calls a web ingestion endpoint. The restricted role needs:

- `SELECT`/`UPDATE` on `scan_job`, `UPDATE` on `worker`;
- `INSERT`/`UPDATE` on `scan_run`, `finding`, `finding_evidence`,
  `finding_status_event`;
- no access to Better Auth tables.

Claiming uses one transaction: expired leases beyond `max_attempts` are failed,
then `FOR UPDATE SKIP LOCKED` selects the next eligible job and marks it
`leased` with a lease expiry. Long scans renew the lease; a lost lease stops the
worker from renewing again but never duplicates findings because ingestion is
transactional and keyed by `(asset_id, stable_key)`.

### Findings

- Stable keys are tool-scoped: `gitleaks|<rule>|<file>|<line>`,
  `osv|<package>|<version>|<id>` and `trivy:<kind>|<target>|<id>...`.
- Re-seeing a finding updates `last_seen_at` and increments occurrences;
  resolved findings are re-opened. A finding absent from **two consecutive
  successful scans** (configurable) is resolved with a status event.
- Secret values are never stored. Gitleaks `Secret`/`Match` and Trivy secret
  matches are never read; only rule, path, line, fingerprint and entropy are kept.
- Every tool must succeed for a run to be `completed` (stricter profile chosen
  for Phase 1). Any tool error fails the run and writes no findings.

### Scanner provisioning and limits

- Gitleaks 8.21.2, OSV-Scanner 1.9.2 and Trivy 0.76.2 are pinned and downloaded
  on first startup into `NEOSHIELD_SCANNER_DIR`; published checksums are verified
  where available. Failure to install leaves that scanner missing and scans fail
  loudly instead of silently skipping coverage.
- Limits: 50 MB archive, 5,000 files, 5 MB per file, 200 MB extracted, 180 s per
  scanner, one job at a time per worker.
- Archives are extracted with a custom filter that strips the GitHub root,
  rejects traversal, links and devices, and bounds total size. Repository code is
  never executed; scanners only read files. Trivy's vulnerability DB is
  downloaded on its first run (needs network and may exceed one timeout).

## Phase 2: endpoints and networks (implemented)

### Wazuh endpoint path

- A Wazuh integration is one `integration` row per workspace
  (`provider = 'wazuh'`, `project_id`, `status`, `metadata.minLevel`,
  `sync_cursor`, `last_synced_at`, `last_error`). The UI sets the project and
  minimum rule level; indexer/manager URLs and credentials stay in the Python
  worker environment and are never sent to the browser or stored in the DB.
- `endpoint` assets are auto-provisioned by the worker from agents
  (identifier `wazuh:<agentId>`, config keys `provider`, `agentId`, `agentName`,
  `hostname`, `ipAddress`, OS fields). A matching `endpoint_agent` row keeps the
  current status, last-seen time and inventory for the asset detail page.
- Every ingested alert above the threshold becomes a redacted `security_event`
  keyed by `(workspace_id, source_tool, external_id)`, so re-polling the same
  Wazuh document is idempotent. Findings use deterministic keys such as
  `wazuh|auth|<agent>|<rule>|<srcip>|<user>` and
  `wazuh|fim|<agent>|<event>|<path>`; the event links to its finding.
- Categories that become findings: authentication, file integrity, malware,
  vulnerability, agent health, configuration and audit. Other alerts remain
  events only. `full_log` and raw payloads are never stored; evidence is an
  allowlist of bounded fields.
- The worker polls continuously while the integration is `pending`, `connected`
  or `error` (and its environment has credentials). It advances `sync_cursor`
  only after a successful batch. `disconnected` stops polling but keeps all
  history. Endpoint jobs run the same path on demand for one agent.
- Agent inventory is optional: the manager API (`/security/user/authenticate`,
  `/agents`) supplies status/OS data, while alerts always come from the indexer
  (`wazuh-alerts-*`, `rule.level`, `agent.id`).

### Authorized Nmap discovery

- A network asset stores an exact authorized scope in `asset.config`:
  `{ provider: "network", cidr, scanProfile, authorization: {
  confirmedByUserId, confirmedAt, statement, scope } }`. The UI requires an
  explicit authorization checkbox and typing the normalized CIDR; both the web
  queue path and the worker re-validate it.
- Allowed scope is IPv4 RFC1918/CGNAT only (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`), prefix `24`–`32`, at most 256 addresses. `network_allow_public`
  stays false and has no UI override.
- Two fixed profiles: `discovery` (`-sn -PE -PS22,80,443`, no service scan) and
  `services` (discovery plus `-sV --version-light` on the explicit
  `NEOSHIELD_NETWORK_PORTS` list, capped at 64 hosts). No NSE, OS detection,
  brute force, exploitation or aggressive timing; Nmap runs as an argv list
  with a timeout and output cap.
- `network_host` is unique per `(asset_id, address)` and `network_service` per
  `(host_id, port, protocol)`. Each scan upserts active observations, marks
  absent ones `missing`, and records a `scan_run` with the CIDR, profile, ports
  and Nmap version.
- Findings: one informational `network|host|<address>` finding per discovered
  host, plus `network|port|<address>|<port>|<protocol>` findings for risky
  services (SSH, RDP, Telnet, SMB, databases, Redis, Docker API, etc.).
  Host findings resolve when a later run no longer sees the host; service
  findings resolve only after a **complete** service-profile run, so a
  discovery-only scan never silently clears service risk.

### Worker permissions

`deploy/sql/worker-grants.sql` adds `SELECT/UPDATE` on `integration`,
`INSERT/UPDATE` on `asset` (auto-provisioned endpoints), and
`SELECT/INSERT/UPDATE` on `endpoint_agent`, `security_event`, `network_host`
and `network_service`. The worker still cannot write Better Auth tables or
delete assets/findings; those remain web-app actions.

### Exposure

Wazuh is deployed from `deploy/lab/wazuh/` at a pinned upstream tag, with every
published port (`1514`, `1515`, `55000`, `9200`, `443`, `514/udp`) bound to
`127.0.0.1`. `verify-exposure.sh` fails if any listener is public. The Nmap
helper in `deploy/compose.lab.yaml` is a one-shot, opt-in container; the
long-running worker is never switched to host networking.

## Failures and freshness

- Worker status is derived: online if `last_seen_at` is within 90 seconds
  (three missed 30-second heartbeats).
- The UI distinguishes "not scanned" from "no findings" and never renders a
  synthetic score. Findings, scores, incidents and reports stay explicitly
  unavailable until their phase lands.
