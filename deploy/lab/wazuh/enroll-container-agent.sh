#!/usr/bin/env bash
# Enroll a containerized Linux endpoint when host sudo is unavailable.
#
#   ./enroll-container-agent.sh
#
# The agent joins the lab's Docker network and talks to the manager service
# directly, so no management port is published. It also adds /var/log/auth.log
# collection and a 30-second FIM cadence so the demo can produce real
# authentication and file-integrity alerts.
set -euo pipefail

AGENT_NAME="${WAZUH_AGENT_NAME:-neoshield-lab-agent}"
CONTAINER="${WAZUH_AGENT_CONTAINER:-neoshield-lab-agent}"
NETWORK="${WAZUH_LAB_NETWORK:-single-node_default}"
MANAGER="${WAZUH_MANAGER_SERVER:-wazuh.manager}"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.10}"

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
  echo "network $NETWORK not found; run ./setup.sh first" >&2
  exit 1
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

echo "starting wazuh-agent:$WAZUH_VERSION as $CONTAINER on $NETWORK"
docker run -d --name "$CONTAINER" --network "$NETWORK" \
  -e WAZUH_MANAGER_SERVER="$MANAGER" \
  -e WAZUH_REGISTRATION_SERVER="$MANAGER" \
  -e WAZUH_AGENT_NAME="$AGENT_NAME" \
  "wazuh/wazuh-agent:$WAZUH_VERSION" >/dev/null

sleep 20

echo "adding auth.log collection and a 30s FIM cadence for the demo"
docker exec "$CONTAINER" sh -c "
  grep -q '/var/log/auth.log' /var/ossec/etc/ossec.conf || \
    sed -i 's#</ossec_config>#  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n</ossec_config>#' /var/ossec/etc/ossec.conf
  sed -i 's#<frequency>43200</frequency>#<frequency>30</frequency>#' /var/ossec/etc/ossec.conf
"
docker restart "$CONTAINER" >/dev/null
sleep 20

MANAGER_CONTAINER="$(docker ps --filter 'name=wazuh.manager' \
  --format '{{.Names}}' | head -1)"
if [ -n "$MANAGER_CONTAINER" ]; then
  echo "manager agent inventory:"
  docker exec "$MANAGER_CONTAINER" /var/ossec/bin/agent_control -l 2>&1 | head -12
fi

cat <<EOF
Containerized Linux agent '$AGENT_NAME' started.
Generate alerts inside it with:

  docker exec $CONTAINER sh -c \\
    'echo "Nov 14 00:00:00 lab sshd[4242]: Failed password for invalid user labuser from 127.0.0.1 port 4242 ssh2" >> /var/log/auth.log'

  docker exec $CONTAINER sh -c 'echo "fim \$(date -u +%FT%TZ)" >> /etc/neoshield-lab-fim.txt'

Wait ~30 seconds, then search the indexer or run an endpoint sync in NeoShield.
EOF
