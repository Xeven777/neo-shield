-- Least-privilege grants for the Python scan worker role.
--
-- Run this once as the database owner after Drizzle migrations, replacing
-- `neoshield_worker` with the role named in NEOSHIELD_DATABASE_URL. The worker
-- never owns the schema and never writes Better Auth tables.
--
--   psql "$DATABASE_URL_UNPOOLED" -v ON_ERROR_STOP=1 \
--     -v worker_role=neoshield_worker -f deploy/sql/worker-grants.sql
--
-- Re-run it after every phase that adds tables the worker writes.

\set ON_ERROR_STOP on
\if :{?worker_role}
\else
  \set worker_role neoshield_worker
\endif

GRANT USAGE ON SCHEMA public TO :"worker_role";

-- Phase 0/1: identity, queue and finding ingestion.
GRANT SELECT ON worker, project, asset TO :"worker_role";
GRANT SELECT, UPDATE ON scan_job TO :"worker_role";
GRANT SELECT, INSERT, UPDATE ON scan_run TO :"worker_role";
GRANT SELECT, INSERT, UPDATE ON finding, finding_evidence TO :"worker_role";
GRANT SELECT, INSERT ON finding_status_event TO :"worker_role";

-- Phase 2: endpoint inventory, event history and network discovery.
GRANT INSERT, UPDATE ON asset TO :"worker_role";
GRANT SELECT, UPDATE ON integration TO :"worker_role";
GRANT SELECT, INSERT, UPDATE ON endpoint_agent TO :"worker_role";
GRANT SELECT, INSERT ON security_event TO :"worker_role";
GRANT SELECT, INSERT, UPDATE ON network_host, network_service TO :"worker_role";

-- Never grant the worker access to Better Auth tables or destructive rights on
-- assets/findings. Asset removal is a web-app action; the worker only upserts.
