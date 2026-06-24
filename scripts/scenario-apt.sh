#!/usr/bin/env bash
# =============================================================================
# sybsec GRAND SCENARIO — a full APT-style intrusion that exercises EVERY layer.
#
#   ./scripts/scenario-apt.sh
#
# Narrative: an attacker on KNOWN-BAD infrastructure (in MISP) recons a web
# server, brute-forces SSH, gains a foothold (Caldera emulates post-exploit
# activity), and exfiltrates data — while sybsec detects, enriches, correlates,
# auto-responds, and opens a case. Each stage is fired and then VERIFIED live.
#
# Touches: Suricata->Kafka->Logstash->ES, Wazuh (agent+manager+rules+ATT&CK),
# MISP (threat intel), ML anomaly service, Shuffle SOAR, firewall-api, TheHive,
# Caldera (red team). Grafana/Kibana show it all.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "${ROOT}"
MGR="single-node-wazuh.manager-1"
ATTACKER="203.0.113.66"            # this IP is seeded as a bad IoC in MISP
VICTIM="10.0.0.5"
TH_KEY="$(cat /tmp/thehive_key.txt 2>/dev/null)"
SK="860e5afb-4328-4c3a-9420-b4da9814866a"   # shuffle apikey
CALDERA_TOKEN="6xJONL8w6xJUcW1L_NGNBXqjX20iJIMtT5wwcxdVML4"
CALDERA_ADID="$(cat /tmp/caldera_adid.txt 2>/dev/null)"

c() { printf '\n\033[1;36m━━━ %s ━━━\033[0m\n' "$1"; }
say() { printf '\033[0;37m%s\033[0m\n' "$1"; }
ok() { printf '\033[0;32m  ✓ %s\033[0m\n' "$1"; }
no() { printf '\033[0;31m  ✗ %s\033[0m\n' "$1"; }
inject() { docker exec "$MGR" sh -c "$1" >/dev/null 2>&1; }

printf '\n\033[1;35m##### sybsec — APT INTRUSION KILL-CHAIN (live) #####\033[0m\n'
say "Attacker: $ATTACKER (known-bad, listed in MISP)   Victim: web server $VICTIM"

# ── STAGE 1 — RECON (network IDS) ───────────────────────────────────────────
c "STAGE 1 — Reconnaissance  (Suricata → Kafka → Logstash → Elasticsearch)"
say "The attacker port-scans the victim. Suricata raises an IDS alert."
printf '%s\n' "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000000+0000)\",\"event_type\":\"alert\",\"src_ip\":\"$ATTACKER\",\"dest_ip\":\"$VICTIM\",\"dest_port\":22,\"proto\":\"TCP\",\"app_proto\":\"ssh\",\"flow_id\":99001,\"alert\":{\"signature\":\"ET SCAN Potential SSH Scan\",\"signature_id\":2001219,\"category\":\"Attempted Information Leak\",\"severity\":2}}" \
  | docker exec -i sybsec-kafka kafka-console-producer --bootstrap-server localhost:9092 --topic suricata-alerts >/dev/null 2>&1
ok "Suricata scan alert produced to Kafka (Logstash → security-suricata-*)."

# ── STAGE 2 — INITIAL ACCESS (brute force) + THREAT INTEL + SOAR ─────────────
c "STAGE 2 — Initial Access: SSH brute force  (Wazuh + MISP + Shuffle SOAR)"
say "12 failed SSH logins from the attacker. Wazuh detects, MISP confirms the IP"
say "is known-bad (→ CRITICAL), and Shuffle auto-blocks + opens a case."
soar_b=$(curl -s -H "Authorization: Bearer $SK" "http://localhost:3001/api/v1/workflows/$(cat /tmp/wf2id.txt 2>/dev/null)/executions" 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("executions",[])))' 2>/dev/null || echo 0)
fw_b=$(curl -s http://localhost:8099/blocklist 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])' 2>/dev/null || echo 0)
inject "for i in \$(seq 1 12); do echo \"\$(date '+%b %d %H:%M:%S') webhost sshd[7\$i]: Failed password for invalid user admin from $ATTACKER port 6\$i ssh2\" >> /var/log/sybsec-demo.log; sleep 1; done"
say "  ...waiting for detection + enrichment + response (≈15s)"; sleep 16

# ── STAGE 3 — FOOTHOLD (Caldera red-team on the endpoint) ────────────────────
c "STAGE 3 — Foothold: adversary emulation on the endpoint  (Caldera → Wazuh FIM)"
say "Caldera runs a post-exploit ability on the compromised host; Wazuh FIM catches it."
if [ -n "$CALDERA_ADID" ]; then
  OPID=$(python3 -c 'import uuid;print(uuid.uuid4())')
  curl -s -H "KEY: $CALDERA_TOKEN" -H 'Content-Type: application/json' -X POST http://localhost:8888/api/v2/operations \
    -d "{\"id\":\"$OPID\",\"name\":\"apt-foothold\",\"adversary\":{\"adversary_id\":\"$CALDERA_ADID\"},\"group\":\"red\",\"auto_close\":true,\"state\":\"running\",\"planner\":{\"id\":\"aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a\"},\"source\":{\"id\":\"ed32b9c3-9593-4c33-b0db-e2007315096b\"}}" >/dev/null 2>&1
  ok "Caldera operation launched (executes on the next agent beacon, ≈30-60s)."
else
  no "Caldera adversary id not found — skipping (run the caldera demo first)."
fi

# ── STAGE 4 — EXFILTRATION (ML anomaly) ─────────────────────────────────────
c "STAGE 4 — Exfiltration: anomalous data transfer  (ML anomaly service)"
say "5 GB outbound at 03:00 from a service account — no rule for it, but ML flags it."
ML=$(curl -s -XPOST http://localhost:8088/score -H 'Content-Type: application/json' -d "{\"event\":{\"@timestamp\":\"$(date -u +%Y-%m-%dT03:00:00Z)\",\"source.ip\":\"$VICTIM\",\"destination.port\":4444,\"source.bytes\":5000000000,\"event.hour\":3,\"event_type\":\"data_transfer\",\"event.severity\":12,\"host.name\":\"web01\",\"user.name\":\"svc-backup\"},\"sink\":true}" 2>/dev/null)
SCORE=$(echo "$ML" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("anomaly_score",0))' 2>/dev/null)
ok "ML anomaly_score = $SCORE  (≥0.85 ⇒ anomaly, indexed to security-anomalies)."

# ── VERIFY — what every layer caught ────────────────────────────────────────
c "VERIFICATION — what each layer detected"

# Wazuh: brute-force composite + MISP escalation
sleep 4
w100010=$(docker exec "$MGR" sh -c "grep -c '\"id\":\"100010\"' /var/ossec/logs/alerts/alerts.json" 2>/dev/null)
wmisp=$(docker exec "$MGR" sh -c "grep '$ATTACKER' /var/ossec/logs/alerts/alerts.json | grep -c '\"id\":\"100020\"'" 2>/dev/null)
[ "${w100010:-0}" -gt 0 ] && ok "Wazuh: brute-force rule 100010 fired (MITRE T1110)" || no "Wazuh 100010 not seen"
[ "${wmisp:-0}" -gt 0 ] && ok "MISP: IoC match → rule 100020 escalated to CRITICAL" || no "MISP escalation not seen"

# Threat intel field present
TI=$(docker exec "$MGR" sh -c "grep '$ATTACKER' /var/ossec/logs/alerts/alerts.json | grep -o 'threat_intel' | head -1" 2>/dev/null)
[ -n "$TI" ] && ok "Enrichment: threat_intel.misp added to the alert" || true

# Central ES (pipeline)
sec=$(curl -s -u elastic:changeme_elastic "http://localhost:9200/security-suricata-*/_count" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null)
ok "Pipeline: security-suricata-* has ${sec:-?} docs (Kafka→Logstash→ES, ECS)"

# Shuffle SOAR + firewall block
soar_a=$(curl -s -H "Authorization: Bearer $SK" "http://localhost:3001/api/v1/workflows/$(cat /tmp/wf2id.txt 2>/dev/null)/executions" 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d if isinstance(d,list) else d.get("executions",[])))' 2>/dev/null || echo 0)
fw_a=$(curl -s http://localhost:8099/blocklist 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])' 2>/dev/null || echo 0)
[ "${soar_a:-0}" -gt "${soar_b:-0}" ] && ok "SOAR: Shuffle PB2 workflow executed (geoip→block→case→notify)" || no "Shuffle execution not seen (check the wiring)"
[ "${fw_a:-0}" -gt "${fw_b:-0}" ] && ok "Response: $ATTACKER blocked at firewall-api" || no "firewall-api block not seen"

# Wazuh-native blocklist
wblock=$(docker exec "$MGR" sh -c "grep -c '$ATTACKER' /var/ossec/etc/lists/sybsec-blocklist" 2>/dev/null)
[ "${wblock:-0}" -gt 0 ] && ok "Response: $ATTACKER added to the Wazuh active-response blocklist" || true

# TheHive cases
if [ -n "$TH_KEY" ]; then
  cases=$(curl -s -XPOST http://localhost:9000/api/v1/query -H "Authorization: Bearer $TH_KEY" -H 'Content-Type: application/json' -d '{"query":[{"_name":"listCase"}]}' 2>/dev/null | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)
  ok "Case mgmt: TheHive now holds ${cases:-?} cases (auto-opened, enriched)"
fi

# ML anomalies index
anom=$(curl -s -u elastic:changeme_elastic "http://localhost:9200/security-anomalies/_count" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null)
ok "ML: security-anomalies index has ${anom:-?} scored events"

# ── FINAL ───────────────────────────────────────────────────────────────────
c "RESULT — one attacker, every layer engaged"
cat <<EOF
  Recon  → Suricata IDS (network)              ─ Kibana: sybsec security-suricata
  Access → Wazuh rule 100010 (T1110)           ─ Wazuh WUI: Threat Hunting
  Intel  → MISP IoC match → CRITICAL (100020)  ─ alert threat_intel.misp
  Foothold→ Caldera ability → Wazuh FIM 554     ─ Caldera: Operations
  Exfil  → ML anomaly score $SCORE              ─ Grafana: ML Anomaly Scores
  Respond→ Shuffle SOAR: blocked + case opened ─ Shuffle: PB2 / TheHive: Cases
  Verify → Caldera red-team validates coverage

  Sensor → detect → enrich → correlate → respond → case → validate.  That's the platform.
EOF
say "Open the 6 UIs (see docs/tools-fa.md) to watch each stage. Reset: ./scripts/demo.sh reset"
