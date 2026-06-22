#!/usr/bin/env bash
# Wazuh active-response: network-isolate this host. Drops all traffic except the
# Wazuh manager (so the agent stays manageable) and loopback. Reversible.
#
# Manager IP must be provided via WAZUH_MANAGER_IP env or parameters.
set -euo pipefail
LOG="/var/ossec/logs/active-responses.log"
read -r INPUT || true

COMMAND=$(echo "${INPUT}" | grep -oE '"command"\s*:\s*"[^"]+"' | cut -d'"' -f4 || echo "add")
MGR="${WAZUH_MANAGER_IP:-$(grep -oE '<address>[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null | head -1 | cut -d'>' -f2 || echo '')}"
ts="$(date '+%Y-%m-%d %H:%M:%S')"
CHAIN="SYBSEC_QUARANTINE"

case "${COMMAND}" in
  add)
    iptables -N "${CHAIN}" 2>/dev/null || iptables -F "${CHAIN}"
    iptables -A "${CHAIN}" -i lo -j ACCEPT
    iptables -A "${CHAIN}" -o lo -j ACCEPT
    if [ -n "${MGR}" ]; then
      iptables -A "${CHAIN}" -d "${MGR}" -j ACCEPT
      iptables -A "${CHAIN}" -s "${MGR}" -j ACCEPT
    fi
    iptables -A "${CHAIN}" -j DROP
    iptables -I INPUT  -j "${CHAIN}"
    iptables -I OUTPUT -j "${CHAIN}"
    echo "${ts} quarantine-host: isolated (manager ${MGR:-none} whitelisted)" >> "${LOG}"
    ;;
  delete)
    iptables -D INPUT  -j "${CHAIN}" 2>/dev/null || true
    iptables -D OUTPUT -j "${CHAIN}" 2>/dev/null || true
    iptables -F "${CHAIN}" 2>/dev/null || true
    iptables -X "${CHAIN}" 2>/dev/null || true
    echo "${ts} quarantine-host: isolation lifted" >> "${LOG}"
    ;;
esac
