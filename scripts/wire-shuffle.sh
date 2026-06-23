#!/usr/bin/env bash
# =============================================================================
# Wire the Wazuh -> Shuffle -> TheHive SOAR loop (Phase A).
#
#   ./scripts/wire-shuffle.sh <SHUFFLE_APIKEY>
#
# The Shuffle API key (>=36 chars) is generated once in the Shuffle UI
# (avatar -> Settings -> API key -> regenerate) because this Shuffle build does
# not provision one headlessly. Everything else is automated:
#   1. import the PB2 workflow (shuffle/playbooks/pb2_bruteforce_shuffle.json),
#      injecting the host IP + TheHive key
#   2. create + start its webhook
#   3. connect the Wazuh manager (and TheHive) to the Shuffle network
#   4. register the Wazuh `shuffle` integration pointing at the webhook
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "${ROOT}"
SK="${1:?usage: wire-shuffle.sh <SHUFFLE_APIKEY>}"
SHURL="${SHUFFLE_URL:-http://localhost:3001}"
MGR="single-node-wazuh.manager-1"
HOSTIP="$(hostname -I | awk '{print $1}')"
KEY="$(cat /tmp/thehive_key.txt 2>/dev/null || true)"
ok() { printf '\033[32m   %s\033[0m\n' "$1"; }

[ -n "${KEY}" ] || { echo "TheHive key not found (/tmp/thehive_key.txt). Run deploy-all.sh wiring first."; exit 1; }

# 1. import workflow (host IP + key injected) -------------------------------
WF=$(sed -e "s|__HOST_IP__|${HOSTIP}|g" -e "s|__THEHIVE_API_KEY__|${KEY}|g" \
      shuffle/playbooks/pb2_bruteforce_shuffle.json)
WFID=$(curl -s -H "Authorization: Bearer $SK" -H 'Content-Type: application/json' \
  -X POST "$SHURL/api/v1/workflows" -d "$WF" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')
[ -n "$WFID" ] || { echo "workflow import failed (check the API key)"; exit 1; }
START=$(curl -s -H "Authorization: Bearer $SK" "$SHURL/api/v1/workflows/$WFID" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["start"])')
ok "workflow imported: $WFID"

# 2. create + start webhook --------------------------------------------------
HID=$(python3 -c 'import uuid;print(uuid.uuid4())')
curl -s -H "Authorization: Bearer $SK" -H 'Content-Type: application/json' -X POST "$SHURL/api/v1/hooks" \
  -d "{\"id\":\"$HID\",\"name\":\"wazuh-bruteforce\",\"type\":\"webhook\",\"workflow\":\"$WFID\",\"start\":\"$START\",\"environment\":\"Shuffle\",\"auth\":\"\",\"running\":true,\"status\":\"running\",\"info\":{\"name\":\"wazuh-bruteforce\",\"url\":\"$SHURL/api/v1/hooks/webhook_$HID\"}}" >/dev/null 2>&1
ok "webhook created: webhook_$HID"

# 3. networking: manager + thehive on the shuffle bridge ---------------------
SNET=$(docker inspect shuffle-backend --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}')
docker network connect "$SNET" "$MGR" 2>/dev/null || true
docker network connect "$SNET" sybsec-thehive 2>/dev/null || true
ok "manager + thehive connected to $SNET"

# 4. register the Wazuh shuffle integration ----------------------------------
docker cp "$MGR":/var/ossec/etc/ossec.conf /tmp/ossec.conf
python3 - "$HID" <<'PY'
import sys
hid=sys.argv[1]; p='/tmp/ossec.conf'; s=open(p).read()
url='http://shuffle-backend:5001/api/v1/hooks/webhook_%s'%hid
import re
if '<name>shuffle</name>' in s:
    s=re.sub(r'(<name>shuffle</name>\s*<hook_url>)[^<]*(</hook_url>)', r'\g<1>%s\g<2>'%url, s)
else:
    block='  <integration>\n    <name>shuffle</name>\n    <hook_url>%s</hook_url>\n    <rule_id>100010,100011,100002,100040,100051</rule_id>\n    <alert_format>json</alert_format>\n  </integration>\n'%url
    i=s.rfind('</ossec_config>'); s=s[:i]+block+s[i:]
open(p,'w').write(s)
PY
docker cp /tmp/ossec.conf "$MGR":/var/ossec/etc/ossec.conf
docker exec "$MGR" sh -c 'chown root:wazuh /var/ossec/etc/ossec.conf'
docker exec "$MGR" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
ok "Wazuh shuffle integration -> webhook_$HID registered + manager reloaded"
echo
ok "Done. Test:  ./scripts/demo.sh bruteforce   then check Shuffle executions + TheHive [SOAR] cases."
