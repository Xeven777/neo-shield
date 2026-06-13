# NeoShield

Unified security intelligence platform. Two services, one database:

- **`web/`** — Next.js app: UI, Better Auth, Drizzle schema/migrations, product APIs. Package manager: **Bun**.
- **`neoshield-python/`** — FastAPI + worker: claims scan jobs, runs Gitleaks / OSV-Scanner / Trivy for repositories, DNS/TLS/HTTP checks for domains, Wazuh alert normalization for endpoints and authorized Nmap discovery for network ranges, writes findings directly to the DB. Python deps: **uv**.
- **Database** — [Neon](https://neon.tech) PostgreSQL (no local DB container). Drizzle is the only migration authority; the worker never alters the schema.

Sign-in: email OTP, magic link, or Google OAuth.

## Run it

### Web (local dev)

```bash
cd web
bun install
cp .env.example .env.local   # set DATABASE_URL (Neon), BETTER_AUTH_SECRET, BETTER_AUTH_URL
bun db:migrate               # applies drizzle/ to Neon
bun dev                      # http://localhost:3000
```

Useful web commands: `bun build` · `bun start` · `bun lint` · `bun typecheck` · `bun db:generate` · `bun db:studio`

### Worker (local dev)

```bash
cd neoshield-python
uv sync
cp .env.example .env         # set web URL, worker token, database URL, GitHub App
uv run uvicorn neoshield.api.main:app --reload --port 8000
```

Get a worker token: sign in → Settings → Worker tokens → New worker → copy the `nsw_…` token into `NEOSHIELD_WORKER_TOKEN`. The worker shows online within ~30s.

Worker checks: `uv run pytest -q` (48 tests) · `uv run ruff check src tests` · `curl -s localhost:8000/health | jq`

### Everything with Docker

```bash
cp deploy/.env.example deploy/.env   # fill in env vars
docker compose --env-file .env up -d   # from deploy/, see deploy/README.md
cd ../web && bun db:migrate            # apply migrations once (not from the container)
```

Local PostgreSQL instead of Neon: add `--profile local-db` (see `deploy/README.md`).

### Endpoint + network (Phase 2)

```bash
# Wazuh lab: pinned single-node stack, localhost-only ports
cd deploy/lab/wazuh
./setup.sh
./enroll-linux-agent.sh         # Debian/Ubuntu endpoint (needs sudo)
# or, no sudo needed: ./enroll-container-agent.sh
./generate-lab-events.sh        # failed SSH logins + a FIM change
./verify-exposure.sh            # fails if a Wazuh port is public
```

`docker compose ... down` from `deploy/lab/wazuh/wazuh-docker/single-node`
stops the lab; `docker rm -f neoshield-lab-agent` removes the container agent.

Set `NEOSHIELD_WAZUH_*` and `NEOSHIELD_NETWORK_*` in the worker environment
(see `neoshield-python/.env.example`), then enable ingestion in
**Integrations → Endpoint monitoring**. Network ranges are added with an exact
CIDR, explicit authorization and a typed confirmation; only private RFC1918/
CGNAT networks up to `/24` are accepted.

## Basic tests

Run these after any change; the first two are the pre-push checks.

```bash
# 1. Web: typecheck, lint, production build
cd web
bun typecheck && bun lint && bun build

# 2. Python: unit tests (Wazuh normalization, Nmap scope/XML/findings) and lint
cd neoshield-python
uv run pytest -q                  # 48 passed
uv run ruff check src tests

# 3. Services reachable
curl -s localhost:3000/sign-in -o /dev/null -w '%{http_code}\n'   # 200
curl -s localhost:8000/health | jq '{status, worker: .worker.status, wazuh: .capabilities.wazuh, nmap: .capabilities.nmap}'
# status "ok"; worker "online"; wazuh.enabled true once configured; nmap path set

# 4. Wazuh lab up and private
docker ps --format '{{.Names}}\t{{.Ports}}'
cd deploy/lab/wazuh && ./verify-exposure.sh
curl -sk -u admin:SecretPassword 'https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?h=index,docs.count'
# all Wazuh ports loopback-only; at least one wazuh-alerts-* index with documents
```

Then check the end-to-end path in the UI:

1. **Worker online** — Overview → Scan worker shows online (heartbeat 30s, offline after 90s).
2. **Endpoint ingestion** — Integrations → Endpoint monitoring → Enable ingestion (pick the project, minimum rule level 5). Within one poll (60s) Assets lists the Wazuh agent as an `endpoint` asset with agent id and status.
3. **Events + findings** — `./generate-lab-events.sh`, wait one poll, open Events: failed SSH logins and the FIM change appear; the endpoint asset shows the matching findings. No `full_log` body is displayed or stored.
4. **Network discovery** — Integrations → Network discovery: add the exact authorized CIDR (for example `172.17.0.0/24`), type the confirmation, then Scan now. Expect one informational finding per live host, plus findings for risky open ports and a service inventory on the asset page.
5. **Scope guard** — `8.8.8.0/24` (public) and `10.0.0.0/16` (wider than `/24`) must be rejected before a job is queued.
6. **Disable stops polling** — turn ingestion off; the sync cursor stops advancing and history stays.

## Before you start

- `neoshield-python/.env` needs the `NEOSHIELD_WAZUH_*` block from
  [deploy/lab/wazuh/README.md](deploy/lab/wazuh/README.md); Wazuh credentials
  live only in the worker environment.
- Network scans run Nmap in the worker. The Docker image includes it; for a
  host-side worker install it with `sudo apt install nmap` (or `NEOSHIELD_NMAP_PATH`).
- Ingestion is enabled per project in **Integrations**; environment variables
  alone do not start a sync.
- Phase 2 tables and worker grants must already be applied: `cd web && bun db:migrate`
  and `psql "$DATABASE_URL" -f deploy/sql/worker-grants.sql` (once per database).

## Docs

- [web/README.md](web/README.md) — env vars, auth, API surface
- [web/docs/architecture.md](web/docs/architecture.md) — schema ownership, worker identity, queue contract
- [neoshield-python/README.md](neoshield-python/README.md) — scanners, limits, contracts
- [deploy/README.md](deploy/README.md) — Compose modes and checks
- [deploy/lab/wazuh/README.md](deploy/lab/wazuh/README.md) — Phase 2 Wazuh lab, agent enrollment, exposure check
- [NeoShield_Specification.md](NeoShield_Specification.md) — full spec
