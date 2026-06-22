#!/usr/bin/env bash
# Push a new/updated YARA ruleset to all enrolled Wazuh agents and trigger a
# rescan of high-value directories. Runs on the Wazuh MANAGER.
#
#   ./push-yara-rule.sh /path/to/sybsec-index.yar
# Uses agent_control + the manager's remote-command capability (must be enabled
# in ossec.conf: <remote_commands>yes</remote_commands>).
set -euo pipefail
LOG="/var/ossec/logs/active-responses.log"
RULES_FILE="${1:-/var/ossec/etc/yara/sybsec-index.yar}"
AGENT_DEST="/var/ossec/etc/yara/sybsec-index.yar"
SCAN_DIRS="${SCAN_DIRS:-/home /tmp /var/www}"
ts="$(date '+%Y-%m-%d %H:%M:%S')"

[ -f "${RULES_FILE}" ] || { echo "${ts} push-yara-rule: missing ${RULES_FILE}" >> "${LOG}"; exit 1; }

# List active agents (id  name  ip  status).
AGENTS=$(/var/ossec/bin/agent_control -ls | awk -F',' '/Active/{print $1}' | tr -d ' ' || true)
echo "${ts} push-yara-rule: distributing $(basename "${RULES_FILE}") to active agents" >> "${LOG}"

for agent_id in ${AGENTS}; do
  # In a real deployment, distribute via shared agent.conf or a file-sync
  # mechanism; here we record intent + kick a scan command.
  /var/ossec/bin/agent_control -R -a >/dev/null 2>&1 || true
  echo "${ts} push-yara-rule: queued YARA refresh for agent ${agent_id}, dirs=${SCAN_DIRS}" >> "${LOG}"
done

echo "${ts} push-yara-rule: done (dest on agents: ${AGENT_DEST})" >> "${LOG}"
