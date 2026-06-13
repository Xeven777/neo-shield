#!/usr/bin/env bash
# Assert that Wazuh management, indexer, enrollment and dashboard ports are
# bound to loopback only. Exits non-zero if any listener is public.
set -euo pipefail

if ! command -v ss >/dev/null 2>&1; then
  echo "ss is required to inspect listeners (iproute2 package)" >&2
  exit 2
fi

TCP_PORTS=(1514 1515 55000 9200 443)
UDP_PORTS=(514)
failed=0

check_tcp() {
  local port="$1"
  local listeners local bad
  listeners="$(ss -H -ltn "sport = :$port" 2>/dev/null || true)"

  if [ -z "$listeners" ]; then
    echo "tcp/$port: not listening (skipped)"
    return
  fi

  while IFS= read -r line; do
    local addr
    addr="$(awk '{print $4}' <<<"$line")"
    if [[ "$addr" =~ ^(127\.0\.0\.1|\[::1\]): ]]; then
      echo "tcp/$port: OK ($addr)"
    else
      echo "tcp/$port: EXPOSED ($addr)" >&2
      failed=1
    fi
  done <<<"$listeners"
}

check_udp() {
  local port="$1"
  local listeners
  listeners="$(ss -H -lun "sport = :$port" 2>/dev/null || true)"

  if [ -z "$listeners" ]; then
    echo "udp/$port: not listening (skipped)"
    return
  fi

  while IFS= read -r line; do
    local addr
    addr="$(awk '{print $4}' <<<"$line")"
    if [[ "$addr" =~ ^(127\.0\.0\.1|\[::1\]): ]]; then
      echo "udp/$port: OK ($addr)"
    else
      echo "udp/$port: EXPOSED ($addr)" >&2
      failed=1
    fi
  done <<<"$listeners"
}

for port in "${TCP_PORTS[@]}"; do
  check_tcp "$port"
done
for port in "${UDP_PORTS[@]}"; do
  check_udp "$port"
done

if [ "$failed" -ne 0 ]; then
  echo >&2
  echo "FAIL: a Wazuh port is publicly bound. Re-apply compose.override.yaml." >&2
  exit 1
fi

echo "OK: no Wazuh management, indexer or dashboard port is publicly bound"
