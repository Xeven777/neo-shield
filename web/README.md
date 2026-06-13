# NeoShield — web app

Unified security intelligence platform. This repository contains the Next.js
application: UI, Better Auth, Drizzle schema/migrations and product APIs. The
Python scanning service lives in a sibling directory (`../neoshield-python`) and
is a separate application.

**Phase 0 status:** email OTP / magic link / Google sign-in, workspace and
project CRUD, the dashboard shell, worker token issuance, worker heartbeat and
online/offline status, Dockerfile and two-service Compose deployment.

## Stack

- Next.js 16 (App Router, React 19, Turbopack), TypeScript, Tailwind CSS 4
- shadcn/ui (Base UI components)
- Better Auth 1.7 (email OTP + magic link + Google, Drizzle adapter)
- Drizzle ORM / Drizzle Kit v1 RC with Neon PostgreSQL (`@neondatabase/serverless`)
- Zod for input validation
- pnpm for packages

## Local setup

Prerequisites: Node 24, pnpm 12, a Neon database (no local PostgreSQL container),
and optionally a Resend key and Google OAuth client.

```bash
pnpm install
cp .env.example .env.local
# fill DATABASE_URL, BETTER_AUTH_SECRET (openssl rand -base64 32), BETTER_AUTH_URL
pnpm db:migrate      # applies drizzle/ to Neon
pnpm dev             # http://localhost:3000
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
pnpm db:generate   # generate SQL from lib/db/schema.ts
pnpm db:migrate    # apply pending migrations
pnpm db:studio     # optional inspection
```

`lib/db/schema.ts` is the single source of truth, including Better Auth tables.
The Python worker must never create or alter tables.

Tables in Phase 0: Better Auth (`user`, `session`, `account`, `verification`),
`workspace`, `workspace_member`, `project`, `asset`, `integration`, `worker`,
`scan_job`, `audit_log`.

## Worker

1. Settings → Worker tokens → New worker.
2. Copy the `nsw_…` token once.
3. Run the Python service with `NEOSHIELD_WORKER_TOKEN` set and
   `NEOSHIELD_WEB_URL` pointing at this app.
4. Overview → Scan worker shows online/offline; the worker heartbeats every 30s
   and is considered offline after 90s.

The worker token is stored only as a SHA-256 hash and can be revoked at any time.

## API surface (Phase 0)

Session-authenticated, workspace-scoped, JSON, `cache-control: no-store`:

- `GET|POST /api/v1/workspaces`
- `GET|POST /api/v1/projects`
- `GET|PATCH|DELETE /api/v1/projects/:projectId`
- `GET|POST /api/v1/workers`
- `DELETE /api/v1/workers/:workerId`

Worker credential endpoints:

- `POST /api/internal/worker/heartbeat` (worker bearer token)
- `POST /api/internal/workers/register` (bootstrap token, first boot only)

Errors use `{ "error": { "code", "message", "details?" } }`. Ownership is always
derived from the session and the active workspace, never from the payload.

## Scripts

```bash
pnpm dev / build / start
pnpm lint / typecheck / format
pnpm db:generate / db:migrate / db:studio
```

## Docker

`Dockerfile` builds a standalone Next.js image. The deployment Compose file lives
in `../deploy/compose.yaml` and runs this app plus the Python service against the
same Neon database — with no PostgreSQL container.

## Decisions and limitations

- Result ingestion path: **direct DB writes by the Python worker** (documented in
  `docs/architecture.md`). Next.js owns user-facing authorization and mutations.
- No findings, incidents, scans, reports or AI explanations are implemented yet;
  those screens state this instead of showing synthetic data.
- No asset creation UI yet — assets arrive with Phase 1 (GitHub, domains) and
  Phase 2 (Wazuh, networks).
- One workspace per user in Phase 0; invites are not implemented.
- Email delivery is Resend over plain HTTP; swap the provider in
  `lib/email/send.ts` if needed.
