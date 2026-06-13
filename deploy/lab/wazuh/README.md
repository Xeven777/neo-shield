# Wazuh endpoint lab (Phase 2)

A pinned, localhost-only Wazuh single-node deployment used to prove NeoShield's
endpoint path: a real Wazuh agent produces real alerts, the Python worker
normalizes them into `security_event` / `finding` rows, and the UI shows the
endpoint asset, event history and findings.

This is a **lab**, not a production SIEM. It runs the official
[`wazuh/wazuh-docker`](https://github.com/wazuh/wazuh-docker) single-node stack
at the pinned tag `v4.14.10` (override with `WAZUH_VERSION`).

## Requirements

- Docker Engine with the Compose plugin, git and curl.
- 4 CPU / 8 GB RAM minimum for manager + indexer + dashboard.
- Linux host: `vm.max_map_count=262144` (the setup script tries passwordless
  sudo and otherwise prints the command).
- Windows/macOS Docker Desktop works, but a Linux endpoint is still required to
  enroll an agent.

## Start

```bash
cd deploy/lab/wazuh
./setup.sh
```

The script:

1. clones `wazuh-docker` at `v4.14.10` (reuses an existing clone),
2. copies `compose.override.yaml` into `single-node/` so every published port is
   bound to `127.0.0.1` (`!override` replaces upstream's port list),
3. generates self-signed indexer certificates with the upstream generator,
4. starts the stack and waits for the indexer,
5. prints the worker environment variables and next steps.

Default credentials are the upstream lab defaults:

| Component | URL | User | Password |
| --- | --- | --- | --- |
| Dashboard | https://127.0.0.1:443 | `admin` | `SecretPassword` |
| Indexer | https://127.0.0.1:9200 | `admin` | `SecretPassword` |
| Manager API | https://127.0.0.1:55000 | `wazuh-wui` | `MyS3cr37P450r.*-` |

Change them for anything beyond a throwaway lab. NeoShield never receives these
through the browser: they live only in `neoshield-python/.env`.

## Enroll a Linux endpoint

On a Debian/Ubuntu host:

```bash
cd deploy/lab/wazuh
WAZUH_MANAGER=127.0.0.1 WAZUH_AGENT_NAME=lab-endpoint ./enroll-linux-agent.sh
```

The agent package is pinned to `WAZUH_VERSION` and connects to the manager on
`127.0.0.1:1515` (enrollment) and `127.0.0.1:1514` (events). If the endpoint is
a different machine, use an SSH tunnel or a private network address — do not
publish `1514/1515/55000/9200/443` to the internet.

### Containerized Linux endpoint (no sudo)

When host `sudo` is unavailable, enroll a Linux agent container instead:

```bash
./enroll-container-agent.sh
```

It joins the `single-node_default` Docker network, registers as
`neoshield-lab-agent`, adds `/var/log/auth.log` collection and sets a 30-second
FIM cadence for the demo, then restarts the agent. This was the path verified
on the development host: the agent reported `Active`, the manager API listed it,
and the indexer produced authentication (`rule.groups: authentication_failed`),
FIM (`rule.groups: syscheck`) and SCA alerts for agent `001`.

Generate auth and FIM alerts inside the container:

```bash
docker exec neoshield-lab-agent sh -c \
  'echo "Nov 14 00:00:00 lab sshd[4242]: Failed password for invalid user labuser from 127.0.0.1 port 4242 ssh2" >> /var/log/auth.log'
docker exec neoshield-lab-agent sh -c \
  'echo "fim $(date -u +%FT%TZ)" >> /etc/neoshield-lab-fim.txt'
```

## Generate events

```bash
./generate-lab-events.sh
```

This performs controlled failed SSH logins (invalid user, `BatchMode`, no
password guessing) and creates/modifies `/etc/neoshield-lab-fim.txt`, which the
default FIM configuration monitors. It writes no real credentials and runs no
exploitation.

## Wire it into NeoShield

In `neoshield-python/.env`:

```dotenv
NEOSHIELD_WAZUH_ENABLED=true
NEOSHIELD_WAZUH_INDEXER_URL=https://127.0.0.1:9200
NEOSHIELD_WAZUH_INDEXER_USERNAME=admin
NEOSHIELD_WAZUH_INDEXER_PASSWORD=SecretPassword
# Self-signed lab certificates only:
NEOSHIELD_WAZUH_INDEXER_VERIFY_TLS=false
NEOSHIELD_WAZUH_MANAGER_URL=https://127.0.0.1:55000
NEOSHIELD_WAZUH_MANAGER_USERNAME=wazuh-wui
NEOSHIELD_WAZUH_MANAGER_PASSWORD='MyS3cr37P450r.*-'
NEOSHIELD_WAZUH_MANAGER_VERIFY_TLS=false
```

Restart the worker. In the web app: **Integrations → Endpoint monitoring →
Enable ingestion**, choose the project and a minimum rule level. The worker's
continuous poller then:

- upserts Wazuh agents as `endpoint` assets and `endpoint_agent` rows,
- stores normalized, redacted alerts as `security_event` rows,
- creates findings for authentication, FIM, malware, vulnerability, agent
  health, configuration and audit categories,
- maps agent events to the endpoint asset and links the event to its finding.

Run an on-demand sync with **Scan now** on the endpoint asset. Raw `full_log`
content and Wazuh credentials are never persisted.

If Docker runs on another host, replace `127.0.0.1` with the private address of
that host; the worker must be able to reach the indexer and manager, and no one
else should.

## Verify no public exposure

```bash
./verify-exposure.sh
```

The script inspects listening TCP/UDP sockets for `1514`, `1515`, `55000`,
`9200`, `443` and `514/udp`, and fails if any listener is not loopback.

For a remote host, also confirm from outside that those ports are closed; a
host firewall (for example `ufw deny 9200/tcp`) is a reasonable second layer.

## Stop / reset

```bash
cd wazuh-docker/single-node
docker compose -f docker-compose.yml -f compose.override.yaml down
# add -v only when you want to discard Wazuh state
```

## Limitations

- Single node, self-signed certificates, lab credentials: not production.
- Indexer/dashboard startup can take a few minutes on first boot.
- The lab is intentionally localhost-only. NeoShield's worker must be on the
  same host, in the same Docker network, or reach it through a private tunnel.
