#!/usr/bin/env bash
# Wazuh active-response: block a source IP with an iptables DROP rule.
# Wazuh invokes AR scripts with a JSON command on stdin (4.x protocol).
#
# Idempotent: will not add a duplicate rule. Supports add/delete.
set -euo pipefail

LOG="/var/ossec/logs/active-responses.log"
read -r INPUT || true

# Parse the AR JSON: {"command":"add"|"delete","parameters":{"alert":{"data":{"srcip":"..."}}}}
COMMAND=$(echo "${INPUT}" | grep -oE '"command"\s*:\s*"[^"]+"' | cut -d'"' -f4 || echo "add")
SRCIP=$(echo "${INPUT}"  | grep -oE '"srcip"\s*:\s*"[^"]+"'   | head -1 | cut -d'"' -f4 || true)

ts="$(date '+%Y-%m-%d %H:%M:%S')"
if [ -z "${SRCIP:-}" ]; then
  echo "${ts} block-ip: no srcip in alert, nothing to do" >> "${LOG}"
  exit 0
fi

case "${COMMAND}" in
  add)
    if iptables -C INPUT -s "${SRCIP}" -j DROP 2>/dev/null; then
      echo "${ts} block-ip: ${SRCIP} already blocked" >> "${LOG}"
    else
      iptables -I INPUT -s "${SRCIP}" -j DROP
      echo "${ts} block-ip: DROP added for ${SRCIP}" >> "${LOG}"
    fi
    ;;
  delete)
    iptables -D INPUT -s "${SRCIP}" -j DROP 2>/dev/null || true
    echo "${ts} block-ip: DROP removed for ${SRCIP}" >> "${LOG}"
    ;;
  *)
    echo "${ts} block-ip: unknown command '${COMMAND}'" >> "${LOG}"
    exit 1
    ;;
esac
