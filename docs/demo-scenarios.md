# sybsec — live demo scenarios

Practical, copy-paste demos that fire **real** detections into the running
stack, plus exactly **where to point** in each UI. All scenarios are driven by
one script:

```bash
./scripts/demo.sh <scenario>     # bruteforce | fim | webattack | sudo | anomaly | suricata | all
```

## Access (the four screens to have open)

| UI | URL | Login | Shows |
|----|-----|-------|-------|
| **Wazuh WUI** | https://localhost:5602 | `admin` / `SecretPassword` | endpoint detections, FIM, MITRE, SCA |
| **Kibana** | http://localhost:5601 | `elastic` / `changeme_elastic` | raw ECS events (central ES) |
| **Grafana** | http://localhost:3000 | `admin` / `changeme_grafana` | SOC metrics, anomaly trend, network |
| **ML API** | http://localhost:8088/health | — | anomaly scoring service |

> The WUI uses a self-signed cert → accept the browser warning. First time in
> Kibana, the data views `sybsec security-*` are already created.

Before you start, optionally clear the screens by setting the Wazuh WUI and
Kibana/Grafana time pickers to **Last 24 hours**.

---

## Scenario 1 — SSH brute force  →  `./scripts/demo.sh bruteforce`

Fires 12 failed SSH logins (1s apart) from `192.0.2.66`.

**What happens:** atomic rule `5710` fires per attempt → Wazuh's built-in
composite `5712` → **our custom rule `100010`** ("Brute force confirmed … trigger
Playbook 2") tagged `sybsec_soar`, mapped to **MITRE T1110**.

**Show it:**
- **Wazuh WUI → Threat Hunting / Security events** → filter `rule.id:100010`.
  Open the alert: see `source.ip`, the rule groups incl. `sybsec_soar`, and the
  **MITRE T1110** tag. Pivot to **MITRE ATT&CK** module → Credential Access.
- **Kibana → Discover → `sybsec security-wazuh`** → search `rule.id:100010`.
  Same alert, ECS-normalized, arrived via Filebeat→Kafka→Logstash.
- **Grafana → SOC Overview** → alert-rate panel ticks up.

> Timing note: events must be ≥~1s apart. A same-second burst won't accumulate
> Wazuh's frequency window — the demo script already spaces them.

## Scenario 2 — File Integrity Monitoring  →  `./scripts/demo.sh fim`

Creates, modifies, then deletes `/var/sybsec-watch/passwords.conf` (real-time FIM).

**What happens:** rule `554` (file added), `550` (checksum changed, with the
diff because `report_changes` is on), `553` (deleted).

**Show it:**
- **Wazuh WUI → File Integrity Monitoring** (or *Endpoint security → Integrity
  monitoring*) → the file appears with added/modified/deleted events and the
  **content diff**. Great visual.
- **Kibana → `sybsec security-wazuh`** → `rule.id:(550 OR 554 OR 553)`.

## Scenario 3 — Web attack / SQLi  →  `./scripts/demo.sh webattack`

Injects a `UNION SELECT … FROM users--` request and a `/../../etc/passwd`
traversal into a web access log.

**What happens:** rule `31104` ("Common web attack"), `31106` (web attack
returned 200) — i.e. a *successful* injection. MITRE **T1190**.

**Show it:**
- **Wazuh WUI → Security events** → `rule.id:(31103 OR 31104 OR 31106)`. Show the
  raw request in `full_log` and the MITRE mapping.

## Scenario 4 — Sudo / privilege abuse  →  `./scripts/demo.sh sudo`

Repeated `sudo` PAM authentication failures for user `bob`.

**What happens:** rule `5503` ("PAM: User login failed") / sudo auth rules.

**Show it:**
- **Wazuh WUI → Security events** → `rule.groups:authentication_failed`.

## Scenario 5 — ML anomaly detection  →  `./scripts/demo.sh anomaly`

POSTs an exfil-shaped event (5 GB out, port 4444, 03:00, failed-auth flavor) to
the ML service with `sink:true`.

**What happens:** ensemble (IForest+HBOS+LOF) scores it **1.0 ≥ 0.85** → indexed
to `security-anomalies` with a `reason` and `top_features`.

**Show it:**
- **ML API:** the script prints the JSON response (score, reason, top_features).
- **Grafana → ML Anomaly Scores** → mean-score line + recent-anomalies table.
- **Kibana → `sybsec security-anomalies`** → the doc with `anomaly_score`,
  `reason`, `top_features`, `per_model`.
- Contrast with a benign event (stays "within learned baseline"):
  ```bash
  curl -s -XPOST localhost:8088/score -H 'Content-Type: application/json' \
    -d '{"event":{"source.ip":"10.0.0.5","destination.port":443,"source.bytes":1200,"event.hour":10,"user.name":"alice"}}'
  ```

## Scenario 6 — Suricata IDS alert (network)  →  `./scripts/demo.sh suricata`

Produces a Suricata EVE alert (SSH scan) to Kafka.

**What happens:** Kafka(suricata-alerts) → Logstash normalizes EVE→ECS →
`security-suricata-*` (with GeoIP on public IPs).

**Show it:**
- **Kibana → `sybsec security-suricata`** → the alert with `rule.name`,
  `source.ip`, `destination.port`, `event.module:suricata`.
- **Grafana → Network Traffic** → Suricata-alerts-by-category panel.

---

## Scenario 7 — Detection → auto TheHive case (Phase 3)  →  `./scripts/demo.sh bruteforce`

The same brute force now also **auto-creates a case** in TheHive via the Wazuh
integration (`custom-thehive.py`).

**What happens:** rule `100010` fires → `integratord` → a TheHive case
("[Brute Force / Credential Stuffing] …", severity HIGH, tags T1110/sybsec).

**Show it:**
- **TheHive → Cases** (http://localhost:9000, `admin@thehive.local` / `secret`,
  org **sybsec**) → the new case appears with the source IP, MITRE T1110, and the
  raw log in the description. Open tasks/observables.
- Narrate: *Cortex would auto-run reputation analyzers on the source IP, and
  Shuffle Playbook 2 would block it at the firewall — those are wired next.*

## Scenario 8 — Wazuh agent endpoint

A real agent (`sybsec-endpoint-01`) is enrolled. Trigger an endpoint-side event:
```bash
docker exec sybsec-wazuh-agent-01 sh -c 'echo tampered >> /var/sybsec-watch/agentfile.conf'
```
**Show it:** **Wazuh WUI → Agents** → `sybsec-endpoint-01` = *Active*; its FIM and
rootcheck events are attributed to that agent (not the manager).

## Suggested 5-minute demo flow

1. `./scripts/demo.sh all` (fires everything), then walk the screens:
2. **Wazuh WUI** — brute force `100010` (+MITRE), FIM diff, web attack, sudo.
3. **Kibana** — same events ECS-normalized in `security-wazuh` / `security-suricata`.
4. **ML API + Grafana** — anomaly score 1.0 with reason; anomaly-score trend.
5. Narrate the chain: *sensor → Kafka → Logstash/Wazuh → ES → (SOAR Playbook 2
   would now block the IP + open a TheHive case — that layer is next).* 

## Cleanup / reset between demos

```bash
# truncate the demo log and remove the FIM test file
docker exec single-node-wazuh.manager-1 sh -c ': > /var/log/sybsec-demo.log; rm -f /var/sybsec-watch/*'
```
