#!/usr/bin/env bash
# Deploy the pinned official Wazuh single-node lab with localhost-only ports.
#
#   ./setup.sh
#
# Requires: git, docker with the compose plugin, curl. The stack is heavy
# (indexer + manager + dashboard); 4 CPU / 8 GB RAM is a realistic minimum.
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.10}"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$LAB_DIR/wazuh-docker}"
STACK_DIR="$REPO_DIR/single-node"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "cannot talk to the Docker daemon (is it running and can this user access it?)" >&2
  exit 1
fi

if [ ! -d "$REPO_DIR/.git" ]; then
  echo "cloning wazuh-docker v$WAZUH_VERSION into $REPO_DIR"
  git clone --depth 1 --branch "v$WAZUH_VERSION" \
    https://github.com/wazuh/wazuh-docker.git "$REPO_DIR"
else
  echo "reusing existing clone at $REPO_DIR"
  git -C "$REPO_DIR" fetch --tags --depth 1 origin "v$WAZUH_VERSION" || true
  git -C "$REPO_DIR" checkout "v$WAZUH_VERSION"
fi

if [ ! -f "$STACK_DIR/docker-compose.yml" ]; then
  echo "expected $STACK_DIR/docker-compose.yml; the upstream layout changed" >&2
  exit 1
fi

cp "$LAB_DIR/compose.override.yaml" "$STACK_DIR/compose.override.yaml"

# The Wazuh indexer requires a higher mmap count. Do not prompt for a password
# in an automated lab script: try passwordless sudo and otherwise print the one
# command the operator must run.
if [ "$(uname -s)" = "Linux" ]; then
  CURRENT="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [ "$CURRENT" -lt 262144 ]; then
    if [ "$(id -u)" -eq 0 ]; then
      sysctl -w vm.max_map_count=262144
    elif sudo -n sysctl -w vm.max_map_count=262144 2>/dev/null; then
      :
    else
      echo "NOTE: run this once with root privileges, then re-run:"
      echo "  sudo sysctl -w vm.max_map_count=262144"
    fi
  fi
fi

cd "$STACK_DIR"

echo "generating self-signed indexer certificates (upstream generator image)"
docker compose -f generate-indexer-certs.yml run --rm generator

echo "starting the pinned Wazuh single-node stack"
docker compose -f docker-compose.yml -f compose.override.yaml up -d

INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-SecretPassword}"

echo "waiting for the indexer on https://127.0.0.1:9200"
for _ in $(seq 1 60); do
  if curl -ksf -u "$INDEXER_USER:$INDEXER_PASSWORD" \
    https://127.0.0.1:9200 >/dev/null 2>&1; then
    echo "indexer is up"
    break
  fi
  sleep 5
done

cat <<EOF

Wazuh lab started with localhost-only ports:
  dashboard  https://127.0.0.1:443     (default admin / SecretPassword)
  indexer    https://127.0.0.1:9200    (default admin / SecretPassword)
  manager    https://127.0.0.1:55000   (API user wazuh-wui / MyS3cr37P450r.*- )

Next:
  1. ./enroll-linux-agent.sh              # host agent (needs sudo)
     ./enroll-container-agent.sh          # containerized Linux agent (no sudo)
  2. ./generate-lab-events.sh             # host: failed SSH logins + FIM change
  3. ./verify-exposure.sh                 # assert no public management port

Worker environment (see neoshield-python/.env.example):
  NEOSHIELD_WAZUH_ENABLED=true
  NEOSHIELD_WAZUH_INDEXER_URL=https://127.0.0.1:9200
  NEOSHIELD_WAZUH_INDEXER_USERNAME=admin
  NEOSHIELD_WAZUH_INDEXER_PASSWORD=SecretPassword
  NEOSHIELD_WAZUH_MANAGER_URL=https://127.0.0.1:55000
  NEOSHIELD_WAZUH_MANAGER_USERNAME=wazuh-wui
  NEOSHIELD_WAZUH_MANAGER_PASSWORD='MyS3cr37P450r.*-'

Change these default credentials before exposing anything, and never publish
the indexer, manager or dashboard ports.
EOF
