# NeoShield — web app

Unified security intelligence platform. This repository contains the Next.js
application: UI, Better Auth, Drizzle schema/migrations and product APIs. The
Python scanning service lives in a sibling directory (`../neoshield-python`) and
is a separate application.

**Phase 2 status:** Phase 1 plus Wazuh endpoint ingestion (agent inventory,
redacted events and normalized findings), a filterable event history, and
authorized Nmap discovery with exact CIDR confirmation, host/service inventory
and exposed-service findings.

## Stack

- Next.js 16 (App Router, React 19, Turbopack), TypeScript, Tailwind CSS 4
- shadcn/ui (Base UI components)
- Better Auth 1.7 (email OTP + magic link + Google, Drizzle adapter)
- Drizzle ORM / Drizzle Kit v1 RC with Neon PostgreSQL (`@neondatabase/serverless`)
- Zod for input validation
- bun for packages

## Local setup

Prerequisites: Bun 1.4, a Neon database (no local PostgreSQL container),
and optionally a Resend key and Google OAuth client.

```bash
bun install
cp .env.example .env.local
# fill DATABASE_URL, BETTER_AUTH_SECRET (openssl rand -base64 32), BETTER_AUTH_URL
bun db:migrate      # applies drizzle/ to Neon
bun dev             # http://localhost:3000
```

Sign in with an email code. In development, when `RESEND_API_KEY` is empty, the
code or magic link is printed to the server console and no email is sent.

### Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | yes | Neon connection string (pooled for the web app) |
| `BETTER_AUTH_SECRET` | yes | Session/token signing, at least 32 characters |
| `BETTER_AUTH_URL` | yes | Public origin; must match the browser URL |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | no | Enables Google sign-in |
| `RESEND_API_KEY` | no* | OTP and magic-link delivery |
| `EMAIL_FROM` | no | Verified Resend sender |
| `WORKER_BOOTSTRAP_TOKEN` | no | Allows first-boot worker registration |
| `AUTH_EMAIL_LOG_CODES` | no | `1` allows code logging in production (avoid) |

\* Required for real email. Without it, development logs the code instead.

Google redirect URI: `${BETTER_AUTH_URL}/api/auth/callback/google`.

## Auth methods

- **Email OTP** — 6 digits, 10-minute expiry, 5 attempts, hashed at rest.
- **Magic link** — single use, 15-minute expiry.
- **Google OAuth** — only shown as enabled when both client credentials exist.

All methods use Better Auth's Drizzle adapter against Neon. Workspace roles are
enforced server-side in the service layer and every API route.

## Database

```bash
bun db:generate   # generate SQL from lib/db/schema.ts
bun db:migrate    # apply pending migrations
bun db:studio     # optional inspection
```

`lib/db/schema.ts` is the single source of truth, including Better Auth tables.
The Python worker must never create or alter tables.

Tables in Phase 0: Better Auth (`user`, `session`, `account`, `verification`),
`workspace`, `workspace_member`, `project`, `asset`, `integration`, `worker`,
`scan_job`, `audit_log`. Phase 1 adds `scan_run`, `finding`, `finding_evidence`,
`finding_status_event`, `github_installation` and `github_repository`. Phase 2
adds `endpoint_agent`, `security_event`, `network_host`, `network_service` and
the integration `sync_cursor` / `last_error` columns.

## Worker

1. Settings → Worker tokens → New worker.
2. Copy the `nsw_…` token once.
3. Run the Python service with `NEOSHIELD_WORKER_TOKEN` set and
   `NEOSHIELD_WEB_URL` pointing at this app.
4. Overview → Scan worker shows online/offline; the worker heartbeats every 30s
   and is considered offline after 90s.
5. Attach a GitHub repository or domain, enable Wazuh ingestion, or add an
   authorized private CIDR in Integrations, then use “Scan now” on the project
   or asset page. Wazuh credentials stay in the worker environment.

The worker token is stored only as a SHA-256 hash and can be revoked at any time.

## API surface

Session-authenticated, workspace-scoped, JSON, `cache-control: no-store`:

- `GET|POST /api/v1/workspaces`
- `GET|POST /api/v1/projects`
- `GET|PATCH|DELETE /api/v1/projects/:projectId`
- `GET|POST /api/v1/workers`
- `DELETE /api/v1/workers/:workerId`
- `GET|POST /api/v1/scans` (repository, domain, endpoint or authorized network asset)
- `GET /api/v1/events` (endpoint event history, filterable and paginated)
- `GET /api/v1/assets/:assetId` (asset detail, Wazuh agent and network inventory)
- `GET /api/v1/findings`, `GET|PATCH /api/v1/findings/:findingId`

Worker credential endpoints:

- `POST /api/internal/worker/heartbeat` (worker bearer token)
- `POST /api/internal/workers/register` (bootstrap token, first boot only)

Errors use `{ "error": { "code", "message", "details?" } }`. Ownership is always
derived from the session and the active workspace, never from the payload.

## Scripts

```bash
bun dev / build / start
bun lint / typecheck / format
bun db:generate / db:migrate / db:studio
```

## Docker

`Dockerfile` builds a standalone Next.js image. The deployment Compose file lives
in `../deploy/compose.yaml` and runs this app plus the Python service against the
same Neon database — with no PostgreSQL container.

## Decisions and limitations

- Result ingestion path: **direct DB writes by the Python worker** (documented in
  `docs/architecture.md`). Next.js owns user-facing authorization and mutations.
- Incidents, health scores, reports and AI explanations arrive in later phases;
  those screens state this instead of showing synthetic data.
- Scan intake covers repositories, domains, Wazuh endpoints and explicitly
  authorized private network ranges. Nmap is limited to RFC1918/CGNAT up to
  `/24`; it never runs public ranges, NSE scripts or exploitation.
- Wazuh indexer/manager credentials are worker-only. The web app stores only the
  project binding, minimum rule level and sync state.
- One workspace per user; invites are not implemented.
- Email delivery is Resend over plain HTTP; swap the provider in
  `lib/email/send.ts` if needed.
