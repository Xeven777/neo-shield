#!/usr/bin/env bash
# Produce controlled Wazuh alerts for the NeoShield demo:
#   * repeated failed SSH authentication attempts
#   * a file integrity monitoring change under /etc
#
# Nothing is exploited: the SSH attempts use an invalid user and BatchMode, and
# the FIM change is a harmless text file.
set -euo pipefail

FAILED_LOGINS="${FAILED_LOGINS:-6}"
LAB_USER="${LAB_USER:-neoshield-intruder}"
TARGET_FILE="${TARGET_FILE:-/etc/neoshield-lab-fim.txt}"

echo "generating $FAILED_LOGINS failed SSH authentication attempts"
for attempt in $(seq 1 "$FAILED_LOGINS"); do
  if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 22 >/dev/null 2>&1; then
    ssh -o BatchMode=yes \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=2 \
      -p 22 "$LAB_USER@127.0.0.1" true >/dev/null 2>&1 || true
  else
    # sshd is not listening locally; emit an auth-facility line that the local
    # Wazuh agent's log collector can read on Debian/Ubuntu.
    logger -p auth.info -t sshd \
      "Failed password for invalid user $LAB_USER from 127.0.0.1 port 5$attempt ssh2" \
      || true
  fi
  sleep 1
done

echo "writing and modifying $TARGET_FILE (monitored by the default FIM config)"
echo "created $(date -u +%FT%TZ)" | sudo tee "$TARGET_FILE" >/dev/null
sleep 2
echo "modified $(date -u +%FT%TZ)" | sudo tee -a "$TARGET_FILE" >/dev/null

cat <<'EOF'

Events generated. Give the agent a few seconds, then check the indexer or the
NeoShield Events page:

  curl -ks -u admin:SecretPassword \
    'https://127.0.0.1:9200/wazuh-alerts-*/_search?q=rule.groups:authentication_failed&size=5'

In NeoShield: Integrations -> Endpoint monitoring -> Enable ingestion, then
Projects -> endpoint asset -> Scan now (or wait for the poller).
EOF
