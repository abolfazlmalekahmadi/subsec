#!/bin/bash
# Configure manager, enroll (port 1515), start the agent (connects on 1514),
# then tail the log so the container stays alive and observable.
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
AGENT_NAME="${WAZUH_AGENT_NAME:-sybsec-endpoint-01}"

# Point the agent at the manager.
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|g" /var/ossec/etc/ossec.conf
sed -i "s|MANAGER_IP|${MANAGER}|g" /var/ossec/etc/ossec.conf || true

# Add a real-time FIM watch so this endpoint produces demoable FIM events.
if ! grep -q "/var/sybsec-watch" /var/ossec/etc/ossec.conf; then
  sed -i "s|</syscheck>|  <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/var/sybsec-watch</directories>\n  </syscheck>|" /var/ossec/etc/ossec.conf || true
fi
mkdir -p /var/sybsec-watch

# Enroll once (idempotent: skip if we already have a key).
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "[agent] enrolling with ${MANAGER} as ${AGENT_NAME}..."
  for i in $(seq 1 10); do
    if /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}"; then break; fi
    echo "[agent] enroll attempt $i failed, retrying..."; sleep 5
  done
fi

/var/ossec/bin/wazuh-control start
echo "[agent] started; tailing ossec.log"
exec tail -f /var/ossec/logs/ossec.log
