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

## Phase 1: repository scanning (implemented)

Scope for this slice is GitHub repositories only. Domain checks (DNS, TLS,
redirects, headers) remain a separate follow-up even though the spec lists them
under Phase 1.

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

## Failures and freshness

- Worker status is derived: online if `last_seen_at` is within 90 seconds
  (three missed 30-second heartbeats).
- The UI distinguishes "not scanned" from "no findings" and never renders a
  synthetic score. Findings, scores, incidents and reports stay explicitly
  unavailable until their phase lands.
