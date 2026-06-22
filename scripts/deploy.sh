#!/usr/bin/env bash
# =============================================================================
# sybsec end-to-end deploy/operations script (dev-scale, single host).
#
#   ./scripts/deploy.sh up            # build + start core stack, wait healthy
#   ./scripts/deploy.sh up --wazuh    # also start the Wazuh profile
#   ./scripts/deploy.sh status        # show per-service health
#   ./scripts/deploy.sh validate      # fire synthetic events, verify pipeline
#   ./scripts/deploy.sh wazuh-certs   # generate Wazuh TLS certs (run once)
#   ./scripts/deploy.sh down          # stop everything
#
# Honest scope: this brings up the DEV stack only. Production (3-node ES,
# 3-broker Kafka, Malcolm, MISP/OpenCTI/TheHive/Cortex) is Kubernetes/Helm.
# See STATUS.md.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# shellcheck disable=SC1091
[ -f .env ] || { echo ">> creating .env from .env.example (CHANGE THE SECRETS)"; cp .env.example .env; }
set -a; . ./.env; set +a

ML_PORT="${ML_PORT:-8088}"
ES_PORT="${ES_PORT:-9200}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"

c_green() { printf '\033[32m%s\033[0m\n' "$1"; }
c_red()   { printf '\033[31m%s\033[0m\n' "$1"; }
c_blue()  { printf '\033[34m%s\033[0m\n' "$1"; }

# Wait until a shell test returns 0, up to N attempts.
wait_for() {
  local name="$1" tries="$2"; shift 2
  printf '   waiting for %s ' "${name}"
  for ((i=1; i<=tries; i++)); do
    if "$@" >/dev/null 2>&1; then echo " ok"; return 0; fi
    printf '.'; sleep 5
  done
  echo " TIMEOUT"; return 1
}

cmd_up() {
  local profiles=()
  [[ "${1:-}" == "--wazuh" ]] && profiles=(--profile wazuh)

  c_blue ">> [1/4] Building images (ml-anomaly)..."
  docker compose build ml-anomaly

  c_blue ">> [2/4] Starting core stack..."
  docker compose "${profiles[@]}" up -d

  c_blue ">> [3/4] Waiting for health..."
  wait_for "elasticsearch" 30 bash -c \
    "curl -fsS -u elastic:${ELASTIC_PASSWORD} http://localhost:${ES_PORT}/_cluster/health | grep -qE 'green|yellow'"
  # Set kibana_system password so Kibana can connect.
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" -X POST \
    "http://localhost:${ES_PORT}/_security/user/kibana_system/_password" \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null 2>&1 || true
  wait_for "kafka"         20 bash -c "docker exec sybsec-kafka kafka-broker-api-versions --bootstrap-server localhost:9092"
  wait_for "ml-anomaly"    20 bash -c "curl -fsS http://localhost:${ML_PORT}/health | grep -q '\"status\":\"ok\"'"
  wait_for "grafana"       20 bash -c "curl -fsS http://localhost:${GRAFANA_PORT}/api/health | grep -q ok"

  c_blue ">> [4/4] Bootstrapping..."
  ./kafka/topics.sh || c_red "  ! kafka topic creation reported an issue"
  apply_ilm_policy

  c_green ">> Core stack up."
  cmd_status
}

apply_ilm_policy() {
  curl -fsS -u "elastic:${ELASTIC_PASSWORD}" -X PUT \
    "http://localhost:${ES_PORT}/_ilm/policy/sybsec-ilm" \
    -H 'Content-Type: application/json' -d '{
      "policy": { "phases": {
        "hot":    { "min_age":"0ms",  "actions": { "rollover": { "max_age":"1d", "max_primary_shard_size":"25gb" } } },
        "warm":   { "min_age":"7d",   "actions": { "shrink": { "number_of_shards": 1 }, "forcemerge": { "max_num_segments": 1 } } },
        "cold":   { "min_age":"30d",  "actions": { "freeze": {} } },
        "delete": { "min_age":"90d",  "actions": { "delete": {} } }
      } }
    }' >/dev/null 2>&1 && echo "   ILM policy sybsec-ilm applied" || echo "   ! ILM policy apply skipped"
}

cmd_status() {
  echo
  printf '%-22s %-10s %s\n' "SERVICE" "STATE" "HEALTH"
  printf '%-22s %-10s %s\n' "----------------------" "----------" "----------"
  docker compose ps --format '{{.Name}}\t{{.State}}\t{{.Health}}' 2>/dev/null | \
    while IFS=$'\t' read -r name state health; do
      printf '%-22s %-10s %s\n' "${name}" "${state}" "${health:-n/a}"
    done
  echo
  echo "Endpoints:"
  echo "  Elasticsearch : http://localhost:${ES_PORT}"
  echo "  Kibana        : http://localhost:${KIBANA_PORT}"
  echo "  Grafana       : http://localhost:${GRAFANA_PORT}"
  echo "  ML anomaly    : http://localhost:${ML_PORT}/health"
}

# Fire synthetic events through the seams we can exercise on one box:
#  1) ML scoring of a benign + a malicious event (HTTP)
#  2) produce a Suricata-shaped alert to Kafka and confirm it lands
cmd_validate() {
  c_blue ">> Synthetic validation"

  echo "   [1] ML service scores a benign event..."
  benign=$(curl -fsS -X POST "http://localhost:${ML_PORT}/score" \
    -H 'Content-Type: application/json' \
    -d '{"event":{"source.ip":"10.0.0.5","destination.port":443,"source.bytes":1200,"event.hour":10,"user.name":"alice"}}')
  echo "       -> ${benign}"

  echo "   [2] ML service scores an exfil/brute-force event..."
  mal=$(curl -fsS -X POST "http://localhost:${ML_PORT}/score" \
    -H 'Content-Type: application/json' \
    -d '{"event":{"source.ip":"10.0.0.5","destination.port":4444,"source.bytes":5000000000,"event.hour":3,"rule.id":"5551","event_type":"authentication_failure","event.severity":12}}')
  echo "       -> ${mal}"

  echo "   [3] Producing a synthetic Suricata alert to Kafka topic suricata-alerts..."
  printf '%s\n' '{"timestamp":"2026-06-21T03:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","signature_id":2001219,"severity":2,"category":"Attempted Information Leak"}}' \
    | docker exec -i sybsec-kafka kafka-console-producer --bootstrap-server localhost:9092 --topic suricata-alerts >/dev/null 2>&1 \
    && c_green "       produced." || c_red "       ! produce failed (is the stack up?)"

  echo "   [4] Reading it back from Kafka (confirms bus delivery)..."
  docker exec sybsec-kafka timeout 10 kafka-console-consumer \
    --bootstrap-server localhost:9092 --topic suricata-alerts \
    --from-beginning --max-messages 1 2>/dev/null | head -1 \
    && c_green "       round-trip ok." || c_red "       ! consume timed out"

  echo
  c_blue ">> NOTE: full pipeline (Logstash->ES index, Wazuh rule fire, SOAR case)"
  c_blue "   requires the Wazuh profile + Logstash settled; see docs/runbooks/."
}

cmd_wazuh_certs() {
  c_blue ">> Generating Wazuh TLS certificates..."
  mkdir -p wazuh/certs
  docker run --rm -v "${ROOT}/wazuh/certs:/certs" \
    "wazuh/wazuh-certs-generator:0.0.2" 2>/dev/null \
    || c_red "   ! cert generation image unavailable; see Wazuh docs for offline cert gen"
  c_green ">> Certs (if generated) are in wazuh/certs/"
}

cmd_down() {
  c_blue ">> Stopping stack..."
  docker compose --profile wazuh --profile sensors down
  c_green ">> Down."
}

case "${1:-}" in
  up)          shift; cmd_up "${1:-}";;
  status|ps)   cmd_status;;
  validate)    cmd_validate;;
  wazuh-certs) cmd_wazuh_certs;;
  down)        cmd_down;;
  *) echo "usage: $0 {up [--wazuh]|status|validate|wazuh-certs|down}"; exit 1;;
esac
