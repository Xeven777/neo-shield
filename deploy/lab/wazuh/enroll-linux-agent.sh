#!/usr/bin/env bash
# Enroll a Debian/Ubuntu Linux endpoint with the lab Wazuh manager.
#
#   WAZUH_MANAGER=127.0.0.1 ./enroll-linux-agent.sh
#
# Run on the endpoint host (it may be the same host as the lab manager). The
# script installs the official Wazuh agent package pinned to WAZUH_VERSION.
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.10}"
WAZUH_MANAGER="${WAZUH_MANAGER:-127.0.0.1}"
AGENT_NAME="${WAZUH_AGENT_NAME:-neoshield-lab-$(hostname -s 2>/dev/null || echo endpoint)}"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "this script supports Debian/Ubuntu hosts only" >&2
  echo "for RPM hosts follow the official Wazuh agent guide for your release" >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required" >&2
  exit 1
fi

echo "installing the Wazuh GPG key and apt repository"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null

sudo apt-get update
sudo WAZUH_MANAGER="$WAZUH_MANAGER" \
  WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y "wazuh-agent=$WAZUH_VERSION-1"

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent

echo "agent '$AGENT_NAME' enrolled against $WAZUH_MANAGER:1515"
echo "check status: sudo /var/ossec/bin/wazuh-control status"
echo "the lab manager keeps ports 1514/1515 bound to 127.0.0.1"
