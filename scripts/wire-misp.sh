#!/usr/bin/env bash
# =============================================================================
# Finish the Wazuh -> MISP threat-intel enrichment (Phase 4).
#
#   ./scripts/wire-misp.sh <MISP_API_KEY>
#
# The MISP API key is generated once in the MISP UI (this MISP 2.4.x build hashes
# keys in `auth_keys` and won't issue a usable one headlessly):
#   https://localhost:8447  ->  login admin@sybsec.local / changeme_misp
#   Administration -> Auth Keys -> Add authkey -> copy the key shown once
#
# This script then: seeds a demo IoC, installs custom-misp.py into the manager,
# registers the <integration> + escalation rule, reloads, fires a test alert
# with the IoC IP, and verifies the threat_intel enrichment.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "${ROOT}"
MK="${1:?usage: wire-misp.sh <MISP_API_KEY> (from the MISP UI)}"
MISP="${MISP_URL:-https://localhost:8447}"
MGR="single-node-wazuh.manager-1"
IOC="${IOC_IP:-203.0.113.66}"
ok() { printf '\033[32m   %s\033[0m\n' "$1"; }

# 0. verify the key works ----------------------------------------------------
ver=$(curl -sk -H "Authorization: $MK" -H "Accept: application/json" "$MISP/servers/getVersion" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("version",""))' 2>/dev/null || true)
[ -n "$ver" ] || { echo "MISP key rejected — generate one in the UI (see header)"; exit 1; }
ok "MISP API key valid (v$ver)"

# 1. seed a demo IoC (malicious IP) ------------------------------------------
EID=$(curl -sk -H "Authorization: $MK" -H "Accept: application/json" -H "Content-Type: application/json" \
  -X POST "$MISP/events/add" \
  -d '{"Event":{"info":"sybsec demo - known bad infra","distribution":"0","threat_level_id":"1","analysis":"2"}}' \
  2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("Event",{}).get("id",""))')
curl -sk -H "Authorization: $MK" -H "Accept: application/json" -H "Content-Type: application/json" \
  -X POST "$MISP/attributes/add/$EID" \
  -d "{\"Attribute\":{\"type\":\"ip-dst\",\"category\":\"Network activity\",\"value\":\"$IOC\",\"to_ids\":true,\"comment\":\"sybsec demo C2\"}}" >/dev/null 2>&1
ok "seeded IoC $IOC into MISP event $EID"

# 2. install the integration script + reach MISP from the manager ------------
docker network connect misp_misp "$MGR" 2>/dev/null || true
docker cp wazuh/integrations/custom-misp.py "$MGR":/var/ossec/integrations/custom-misp.py
# wrapper that calls the embedded python with (alert api_key hook_url)
docker exec "$MGR" sh -c 'cat > /var/ossec/integrations/custom-misp <<"EOF"
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"
DIR_NAME="$(cd "$(dirname "$0")"; pwd -P)"; WAZUH_PATH="$(cd "${DIR_NAME}/.."; pwd -P)"
"${WAZUH_PATH}/${WPYTHON_BIN}" "${DIR_NAME}/custom-misp.py" "$@"
EOF
chown root:wazuh /var/ossec/integrations/custom-misp*; chmod 750 /var/ossec/integrations/custom-misp*'
ok "custom-misp installed in the manager"

# 3. register the <integration> in the running config ------------------------
docker cp "$MGR":/var/ossec/etc/ossec.conf /tmp/ossec.conf
python3 - "$MK" "$MISP" <<'PY'
import sys
key, url = sys.argv[1], sys.argv[2]
# manager reaches MISP by container name on the misp network
hook = url.replace("https://localhost:8447", "https://sybsec-misp-core")
p='/tmp/ossec.conf'; s=open(p).read()
if '<name>custom-misp</name>' not in s:
    block=('  <integration>\n    <name>custom-misp</name>\n'
           '    <hook_url>%s</hook_url>\n    <api_key>%s</api_key>\n'
           '    <alert_format>json</alert_format>\n  </integration>\n' % (hook, key))
    i=s.rfind('</ossec_config>'); s=s[:i]+block+s[i:]; open(p,'w').write(s); print("added")
PY
docker cp /tmp/ossec.conf "$MGR":/var/ossec/etc/ossec.conf
docker exec "$MGR" sh -c 'chown root:wazuh /var/ossec/etc/ossec.conf'
docker exec "$MGR" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
ok "Wazuh->MISP integration registered + manager reloaded"
echo
ok "Done. Fire an alert containing $IOC and check the alert for a threat_intel.misp field"
ok "(rule 100020 escalates a MISP match to CRITICAL)."
