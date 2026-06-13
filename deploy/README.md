# NeoShield deployment

One Compose file, two independent images, one PostgreSQL database (Neon or local).

## Deployment modes

Choose one mode — the `docker compose` command differs:

### 1) Neon (managed) — default

```bash
cp deploy/.env.example deploy/.env
# set NEON_DATABASE_URL (and all other env vars)
docker compose --env-file .env up -d
# apply migrations once (from the web repo, not the container)
cd ../web && bun db:migrate
```

### 2) Local PostgreSQL

```bash
cp deploy/.env.example deploy/.env
# set LOCAL_POSTGRES=1 and POSTGRES_USER/PASSWORD/DB as needed
docker compose --env-file .env --profile local-db up -d
# apply migrations once (from the web repo, not the container)
cd ../web && bun db:migrate
```

## Architecture

- **web** (Next.js + Better Auth + Drizzle) on port 3000
- **worker** (FastAPI + heartbeat) on port 8000, not published
- **postgres** — only in the `local-db` profile; a `postgres:16-alpine` service
  with a `pg_data` volume. In Neon mode there is no postgres service; both
  containers connect to your external Neon database.

Both services share the private `neoshield` network. Only the web service is
reachable from the host; the worker talks to it and to PostgreSQL over the
compose network.

## Check

```bash
# Neon (no pg service):
docker compose ps
curl -s localhost:3000/sign-in -o /dev/null -w '%{http_code}\n'

# Local pg:
docker compose --profile local-db ps
curl -s localhost:3000/sign-in -o /dev/null -w '%{http_code}\n'
docker compose exec worker python -c \
  "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"
```

## Notes

- `BETTER_AUTH_URL` must be the public origin of the web app, otherwise OAuth
  redirects and session cookies will not work.
- The worker image includes Nmap. Repository scanner binaries are downloaded
  on first startup into `NEOSHIELD_SCANNER_DIR`.
- Phase 2 adds Wazuh endpoint ingestion and authorized Nmap discovery. Wazuh
  runs as a separate lab stack (`deploy/lab/wazuh/`), not in this compose file,
  and binds every management port to `127.0.0.1`.
- The worker role needs the Phase 2 grants in `deploy/sql/worker-grants.sql`
  (`integration`, `endpoint_agent`, `security_event`, `network_host`,
  `network_service`). Re-run that file after pulling schema changes.
- Do not mount the Docker socket into either container.
- Result ingestion: **direct DB writes by the Python worker** using a restricted
  Neon role (or local Postgres with the same grants). The web app does not
  expose a parallel ingestion endpoint.
- Migrations are applied from the **web** repo (`bun db:migrate`), not from
  the worker container.
