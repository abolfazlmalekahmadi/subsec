#!/usr/bin/env bash
# =============================================================================
# sybsec — ONE-COMMAND full deployment + wiring.
#
# The platform spans 6 docker-compose stacks plus imperative wiring that pure
# `docker compose up` cannot do (network joins, TLS cert generation, TheHive
# API-key creation + injection, Wazuh integration install, agent enrollment,
# Kafka topics, ILM, Kibana data views). This script does all of it, in order,
# idempotently.
#
#   ./scripts/deploy-all.sh           # bring everything up + wire it
#   ./scripts/deploy-all.sh down      # stop every stack
#
# Honest scope: dev single-host. Production = Kubernetes/Helm (see STATUS.md).
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "${ROOT}"
[ -f .env ] || cp .env.example .env
set -a; . ./.env; set +a

ES_AUTH="elastic:${ELASTIC_PASSWORD:-changeme_elastic}"
b() { printf '\033[34m\n=== %s ===\033[0m\n' "$1"; }
ok() { printf '\033[32m   %s\033[0m\n' "$1"; }
wait_http() { local n="$1" u="$2" t="${3:-40}"; printf '   waiting %s ' "$n"
  for ((i=0;i<t;i++)); do c=$(curl -sk -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
    [[ "$c" == 2* || "$c" == 3* ]] && { echo " ok"; return 0; }; printf '.'; sleep 5; done
  echo " TIMEOUT($c)"; return 1; }

cmd_up() {
  # 1) CORE -----------------------------------------------------------------
  b "1/7 Core stack (ES, Kafka, Logstash, ML, Grafana, Kibana)"
  docker compose build ml-anomaly
  docker compose up -d
  wait_http "elasticsearch" "http://localhost:${ES_PORT:-9200}/_cluster/health" 40
  curl -fsS -u "$ES_AUTH" -XPOST "http://localhost:${ES_PORT:-9200}/_security/user/kibana_system/_password" \
    -H 'Content-Type: application/json' -d "{\"password\":\"${KIBANA_PASSWORD:-changeme_kibana}\"}" >/dev/null 2>&1 || true
  wait_http "ml-anomaly" "http://localhost:${ML_PORT:-8088}/health" 20
  ./kafka/topics.sh >/dev/null 2>&1 && ok "kafka topics created" || ok "kafka topics (already exist)"
  curl -fsS -u "$ES_AUTH" -XPUT "http://localhost:${ES_PORT:-9200}/_ilm/policy/sybsec-ilm" \
    -H 'Content-Type: application/json' -d '{"policy":{"phases":{"hot":{"min_age":"0ms","actions":{"rollover":{"max_age":"1d","max_primary_shard_size":"25gb"}}},"delete":{"min_age":"90d","actions":{"delete":{}}}}}}' >/dev/null 2>&1 && ok "ILM policy applied"
  # Index template so the ML anomalies index maps event.module/source.ip
  # consistently with the Wazuh/Suricata indices (else Grafana terms aggs 400).
  curl -fsS -u "$ES_AUTH" -XPUT "http://localhost:${ES_PORT:-9200}/_index_template/sybsec-security-anomalies" \
    -H 'Content-Type: application/json' --data-binary @elasticsearch/index-template.json >/dev/null 2>&1 && ok "ES index template applied"

  # 2) WAZUH single-node ----------------------------------------------------
  b "2/7 Wazuh (indexer + manager + dashboard/WUI)"
  if [ ! -f wazuh/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
    ok "generating Wazuh certs"
    (cd wazuh/single-node && docker compose -f generate-indexer-certs.yml run --rm generator >/dev/null 2>&1) || true
  fi
  (cd wazuh/single-node && docker compose up -d)
  wait_http "wazuh-indexer" "https://localhost:9201/_cluster/health" 30 || true
  wait_http "wazuh-WUI" "https://localhost:5602/" 30 || true

  # 3) Wazuh -> Kafka forwarder + 4) agent ----------------------------------
  b "3/7 Wazuh alert forwarder (alerts.json -> Kafka)"
  (cd wazuh/filebeat-forwarder && docker compose up -d) && ok "forwarder up"
  b "4/7 Wazuh agent (enrolls with manager)"
  (cd wazuh/agent && docker compose up -d --build) && ok "agent up"

  # 5) TheHive + Cortex -----------------------------------------------------
  b "5/7 TheHive + Cortex (case management)"
  (cd thehive && docker compose up -d)
  wait_http "thehive" "http://localhost:9000/api/status" 40
  wait_http "cortex" "http://localhost:9001/api/status" 30 || true
  curl -s -XPOST http://localhost:9001/api/maintenance/migrate -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1 || true

  # 6) Shuffle --------------------------------------------------------------
  b "6/7 Shuffle (SOAR)"
  (cd shuffle/deploy && [ -f .env ] || cp .env.example .env; docker compose up -d) && ok "shuffle up"

  # 7) WIRING ---------------------------------------------------------------
  b "7/7 Cross-stack wiring"
  wire_thehive
  wire_kibana_dataviews
  ok "wiring complete"

  b "Preflight"
  ./scripts/demo.sh preflight || true
  echo; ok "All stacks up. See docs/DEMO.md for the walkthrough."
}

# Create TheHive org+user+key, connect networks, install the Wazuh integration,
# inject the key into the running manager, reload. Idempotent.
wire_thehive() {
  local TH=http://localhost:9000 ADMIN='admin@thehive.local:secret'
  curl -s -u "$ADMIN" -XPOST $TH/api/v1/organisation -H 'Content-Type: application/json' \
    -d '{"name":"sybsec","description":"sybsec SOC"}' >/dev/null 2>&1 || true
  curl -s -u "$ADMIN" -XPOST $TH/api/v1/user -H 'Content-Type: application/json' \
    -d '{"login":"soc-bot@sybsec.local","name":"SOC Automation","organisation":"sybsec","profile":"org-admin"}' >/dev/null 2>&1 || true
  local KEY; KEY=$(curl -s -u "$ADMIN" -XPOST $TH/api/v1/user/soc-bot@sybsec.local/key/renew 2>/dev/null)
  case "$KEY" in *NotFound*|"") ok "thehive key: reuse existing (set manually if blank)";; *) ok "thehive service key issued";; esac

  docker network connect single-node_default sybsec-thehive 2>/dev/null || true
  docker cp wazuh/integrations/custom-thehive.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-thehive.py
  docker cp wazuh/integrations/custom-thehive   single-node-wazuh.manager-1:/var/ossec/integrations/custom-thehive
  docker exec single-node-wazuh.manager-1 sh -c 'chown root:wazuh /var/ossec/integrations/custom-thehive*; chmod 750 /var/ossec/integrations/custom-thehive*'

  if [ -n "${KEY}" ] && [ "${KEY#*NotFound}" = "${KEY}" ]; then
    docker exec single-node-wazuh.manager-1 python3 - "$KEY" <<'PYEOF' || true
import sys,re
key=sys.argv[1]; p='/var/ossec/etc/ossec.conf'; s=open(p).read()
block='  <integration>\n    <name>custom-thehive</name>\n    <hook_url>http://sybsec-thehive:9000</hook_url>\n    <api_key>%s</api_key>\n    <rule_id>100002,100010,100011,100040,100051</rule_id>\n    <alert_format>json</alert_format>\n  </integration>\n'%key
if 'custom-thehive' not in s:
    i=s.rfind('</ossec_config>'); s=s[:i]+block+s[i:]
else:
    s=re.sub(r'<api_key>.*?</api_key>','<api_key>%s</api_key>'%key,s,count=1)
open(p,'w').write(s)
PYEOF
    docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
    ok "Wazuh->TheHive integration wired + manager reloaded"
  fi
}

wire_kibana_dataviews() {
  for pat in security-wazuh security-suricata security-anomalies; do
    curl -s -u "$ES_AUTH" -XPOST "http://localhost:${KIBANA_PORT:-5601}/api/data_views/data_view" \
      -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
      -d "{\"data_view\":{\"title\":\"${pat}-*\",\"name\":\"sybsec ${pat}\",\"timeFieldName\":\"@timestamp\"}}" >/dev/null 2>&1 || true
  done
  ok "kibana data views ensured"
}

cmd_down() {
  b "Stopping every stack"
  (cd shuffle/deploy && docker compose down) 2>/dev/null || true
  (cd thehive && docker compose down) 2>/dev/null || true
  (cd wazuh/agent && docker compose down) 2>/dev/null || true
  (cd wazuh/filebeat-forwarder && docker compose down) 2>/dev/null || true
  (cd wazuh/single-node && docker compose down) 2>/dev/null || true
  docker compose down 2>/dev/null || true
  ok "all stacks stopped"
}

case "${1:-up}" in
  up)   cmd_up;;
  down) cmd_down;;
  *) echo "usage: $0 {up|down}"; exit 1;;
esac
