#!/usr/bin/env bash
# Wazuh active-response: append a source IP to the sybsec firewall blocklist.
# Container-friendly stand-in for an iptables/pfSense block (no NET_ADMIN needed)
# — in production a firewall (pfSense alias / iptables ipset) consumes this list.
# Wazuh 4.x AR protocol: a JSON command arrives on stdin.
set -euo pipefail
LOG="/var/ossec/logs/active-responses.log"
BLOCKLIST="/var/ossec/etc/lists/sybsec-blocklist"
mkdir -p "$(dirname "$BLOCKLIST")"; touch "$BLOCKLIST"

read -r INPUT || true
COMMAND=$(echo "${INPUT}" | grep -oE '"command"[ ]*:[ ]*"[^"]+"' | cut -d'"' -f4 || echo "add")
SRCIP=$(echo "${INPUT}"  | grep -oE '"srcip"[ ]*:[ ]*"[^"]+"'   | head -1 | cut -d'"' -f4 || true)
ts="$(date '+%Y-%m-%d %H:%M:%S')"

if [ -z "${SRCIP:-}" ]; then
  echo "${ts} sybsec-blocklist: no srcip in alert" >> "${LOG}"; exit 0
fi

case "${COMMAND}" in
  add)
    if grep -qE "^${SRCIP}:" "${BLOCKLIST}" 2>/dev/null; then
      echo "${ts} sybsec-blocklist: ${SRCIP} already blocked" >> "${LOG}"
    else
      # CDB-list format "key:value" so Wazuh rules can match on it too
      echo "${SRCIP}:blocked_${ts// /_}" >> "${BLOCKLIST}"
      echo "${ts} sybsec-blocklist: BLOCKED ${SRCIP} (added to firewall blocklist)" >> "${LOG}"
    fi
    ;;
  delete)
    grep -vE "^${SRCIP}:" "${BLOCKLIST}" > "${BLOCKLIST}.tmp" 2>/dev/null || true
    mv "${BLOCKLIST}.tmp" "${BLOCKLIST}" 2>/dev/null || true
    echo "${ts} sybsec-blocklist: UNBLOCKED ${SRCIP}" >> "${LOG}"
    ;;
esac
