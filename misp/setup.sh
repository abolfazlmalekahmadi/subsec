#!/usr/bin/env bash
# Configure a running MISP: enable default feeds, create an automation API key,
# and verify connectivity. Requires MISP_URL + MISP_API_KEY (admin) in env.
#
#   MISP_URL=https://misp.local MISP_API_KEY=xxxx ./misp/setup.sh
#
# Enables the standard community feeds: CIRCL OSINT, Abuse.ch, AlienVault OTX.
set -euo pipefail

MISP_URL="${MISP_URL:-https://localhost}"
MISP_API_KEY="${MISP_API_KEY:?set MISP_API_KEY (admin automation key)}"
CURL=(curl -sS -k -H "Authorization: ${MISP_API_KEY}" -H "Accept: application/json" -H "Content-Type: application/json")

echo ">> Verifying MISP at ${MISP_URL}"
"${CURL[@]}" "${MISP_URL}/servers/getVersion" | grep -q version || { echo "MISP unreachable"; exit 1; }

echo ">> Enabling default feeds (CIRCL, Abuse.ch, OTX)..."
# Pull the feed list, enable feeds whose provider matches our allow-list.
FEEDS_JSON="$("${CURL[@]}" "${MISP_URL}/feeds/index")"
echo "${FEEDS_JSON}" | python3 - "$MISP_URL" "$MISP_API_KEY" <<'PY'
import json, sys, urllib.request, ssl
url, key = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
feeds = json.load(sys.stdin)
allow = ("CIRCL", "abuse.ch", "Abuse.ch", "AlienVault", "OTX", "Botvrij")
def post(path):
    req = urllib.request.Request(url+path, headers={"Authorization":key,"Accept":"application/json"}, method="POST")
    try: urllib.request.urlopen(req, context=ctx, timeout=20); return True
    except Exception as e: print("   ! ", path, e); return False
n=0
for f in feeds:
    feed=f.get("Feed",{})
    if any(a in (feed.get("provider","")+feed.get("name","")) for a in allow):
        fid=feed.get("id")
        if post(f"/feeds/enable/{fid}"):
            print(f"   + enabled feed {fid}: {feed.get('name')}")
            n+=1
print(f">> enabled {n} feeds")
PY

echo ">> Triggering initial feed fetch (may take a while)..."
"${CURL[@]}" -X POST "${MISP_URL}/feeds/fetchFromAllFeeds" >/dev/null 2>&1 || \
  echo "   ! fetchFromAllFeeds returned non-200 (often still queued)"

echo ">> Done. Wazuh<->MISP lookup: deploy wazuh/integrations/custom-misp.py and"
echo "   set MISP_URL/MISP_API_KEY in the Wazuh manager integration block."
