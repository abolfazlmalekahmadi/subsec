#!/usr/bin/env bash
# =============================================================================
# sybsec live-demo trigger. Fires synthetic-but-real attacks into the running
# stack so you can show detections in the Wazuh WUI, Kibana, Grafana, and the
# ML service. See docs/demo-scenarios.md for what to point at in each UI.
#
#   ./scripts/demo.sh bruteforce     SSH brute force  -> Wazuh rule 100010 (T1110)
#   ./scripts/demo.sh fim            File tamper      -> Wazuh FIM 550/554
#   ./scripts/demo.sh webattack      SQLi in web log  -> Wazuh web rules (T1190)
#   ./scripts/demo.sh sudo           Sudo abuse       -> Wazuh auth rules
#   ./scripts/demo.sh anomaly        ML anomaly       -> security-anomalies index
#   ./scripts/demo.sh suricata       IDS alert        -> security-suricata index
#   ./scripts/demo.sh all            run every scenario
# =============================================================================
set -euo pipefail

WAZUH_MGR="${WAZUH_MGR:-single-node-wazuh.manager-1}"
KAFKA="${KAFKA:-sybsec-kafka}"
ML_URL="${ML_URL:-http://localhost:8088}"
ES_AUTH="${ES_AUTH:-elastic:changeme_elastic}"

log()  { printf '\033[34m>> %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m   %s\033[0m\n' "$1"; }

inject() { docker exec "${WAZUH_MGR}" sh -c "$1"; }

scn_bruteforce() {
  log "Scenario: SSH brute force (12 failures, 1s apart, from 192.0.2.66)"
  inject '
    for i in $(seq 1 12); do
      echo "$(date "+%b %d %H:%M:%S") webhost sshd[9$i]: Failed password for invalid user admin from 192.0.2.66 port 5$i ssh2" >> /var/log/sybsec-demo.log
      sleep 1
    done'
  ok "Done. Watch Wazuh WUI -> Security events: rule 5710 x N -> 5712 -> 100010 (sybsec)."
  ok "MITRE: T1110. Also lands in central ES security-wazuh-* (Kibana/Grafana)."
}

scn_fim() {
  log "Scenario: File Integrity Monitoring (create/modify/delete in /var/sybsec-watch)"
  inject 'mkdir -p /var/sybsec-watch
    echo "v1 secrets" > /var/sybsec-watch/passwords.conf; sleep 2
    echo "tampered by attacker" >> /var/sybsec-watch/passwords.conf; sleep 2
    rm -f /var/sybsec-watch/passwords.conf'
  ok "Done. Wazuh WUI -> Integrity monitoring: 554 (added), 550 (modified), 553 (deleted)."
}

scn_webattack() {
  log "Scenario: SQL injection attempt in an Apache access log"
  inject 'cat >> /var/log/sybsec-demo.log <<EOF
$(date "+%b %d %H:%M:%S") webhost apache: 203.0.113.50 - - [22/Jun/2026:07:00:00 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%20password%20FROM%20users-- HTTP/1.1" 200 1234
$(date "+%b %d %H:%M:%S") webhost apache: 203.0.113.50 - - [22/Jun/2026:07:00:01 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0
EOF'
  ok "Done. Wazuh WUI -> Security events: web attack / SQLi rules (31103 etc.), MITRE T1190."
}

scn_sudo() {
  log "Scenario: repeated sudo authentication failures (privilege abuse)"
  inject '
    for i in $(seq 1 5); do
      echo "$(date "+%b %d %H:%M:%S") webhost sudo: pam_unix(sudo:auth): authentication failure; logname=bob ruser=bob rhost= user=bob" >> /var/log/sybsec-demo.log
      sleep 1
    done'
  ok "Done. Wazuh WUI -> Security events: sudo auth-failure rules (5402/5404)."
}

scn_anomaly() {
  log "Scenario: ML anomaly (exfil + odd-hour + auth-fail), pushed to ES"
  resp=$(curl -s -X POST "${ML_URL}/score" -H 'Content-Type: application/json' -d '{
    "event":{"@timestamp":"2026-06-22T03:00:00Z","source.ip":"10.0.0.5","destination.port":4444,
    "source.bytes":5000000000,"event.hour":3,"rule.id":"5551","event_type":"authentication_failure",
    "event.severity":12,"host.name":"wks-07","user.name":"svc-backup"},"sink":true}')
  echo "   ML response: ${resp}"
  ok "Done. Grafana -> 'ML Anomaly Scores'; Kibana data view 'sybsec security-anomalies'."
}

scn_suricata() {
  log "Scenario: Suricata IDS alert (SSH scan) via Kafka -> Logstash -> ES"
  printf '%s\n' '{"timestamp":"2026-06-22T07:30:00.000000+0000","event_type":"alert","src_ip":"45.83.64.1","src_port":40000,"dest_ip":"10.0.0.5","dest_port":22,"proto":"TCP","app_proto":"ssh","flow_id":777,"alert":{"signature":"ET SCAN Potential SSH Scan OUTBOUND","signature_id":2001219,"category":"Attempted Information Leak","severity":2}}' \
    | docker exec -i "${KAFKA}" kafka-console-producer --bootstrap-server localhost:9092 --topic suricata-alerts >/dev/null 2>&1
  ok "Done. Grafana -> 'Network Traffic'; Kibana data view 'sybsec security-suricata'."
}

scn_preflight() {
  log "Preflight: are all demo surfaces up?"
  check() {
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$2" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "302" ]; then ok "UP   $1 ($code)  $2"
    else printf '\033[31m   DOWN %s (%s)  %s\033[0m\n' "$1" "$code" "$2"; fi
  }
  check "Wazuh WUI " "https://localhost:5602/"
  check "Kibana    " "http://localhost:5601/api/status"
  check "Grafana   " "http://localhost:3000/api/health"
  check "ML service" "http://localhost:8088/health"
  check "TheHive   " "http://localhost:9000/api/status"
  check "Cortex    " "http://localhost:9001/api/status"
  check "Shuffle   " "http://localhost:3001/"
  agents=$(docker exec "${WAZUH_MGR}" /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active")
  ok "Wazuh agents Active: ${agents}"
}

scn_reset() {
  log "Reset: clearing the demo log and FIM watch files"
  docker exec "${WAZUH_MGR}" sh -c ': > /var/log/sybsec-demo.log; rm -f /var/sybsec-watch/*' 2>/dev/null || true
  docker exec sybsec-wazuh-agent-01 sh -c 'rm -f /var/sybsec-watch/*' 2>/dev/null || true
  ok "Done. (Existing TheHive cases / ES docs are kept — delete in their UIs if needed.)"
}

case "${1:-}" in
  preflight)  scn_preflight;;
  bruteforce) scn_bruteforce;;
  fim)        scn_fim;;
  webattack)  scn_webattack;;
  sudo)       scn_sudo;;
  anomaly)    scn_anomaly;;
  suricata)   scn_suricata;;
  reset)      scn_reset;;
  all)        scn_bruteforce; scn_fim; scn_webattack; scn_sudo; scn_anomaly; scn_suricata;;
  *) grep -E '^#   \./scripts/demo\.sh' "$0" | sed 's/^#   //'; echo "  ./scripts/demo.sh preflight | reset"; exit 1;;
esac
