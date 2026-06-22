# sybsec — full step-by-step demo runbook

A presenter's script to show **every capability** end to end (~15 min). Each
step has three lines:
- **Run** — the exact command (in the repo root).
- **Show** — which screen to switch to and what to point at.
- **Say** — the one-sentence talking point.

> Format conventions: `🖥️` = browser tab to open, `▶` = terminal command.

---

## 0. Before the demo — preflight (2 min)

**▶ Run:**
```bash
cd /home/abolfazl/Dev/abolfazl/sybsec
./scripts/demo.sh preflight     # everything should be UP / Active
./scripts/demo.sh reset         # clean slate for detections
```

**🖥️ Open these 5 browser tabs** (accept the self-signed cert warnings):

| Tab | URL | Login |
|----|-----|-------|
| Wazuh WUI | https://localhost:5602 | `admin` / `SecretPassword` |
| Kibana | http://localhost:5601 | `elastic` / `changeme_elastic` |
| Grafana | http://localhost:3000 | `admin` / `changeme_grafana` |
| TheHive | http://localhost:9000 | `admin@thehive.local` / `secret` |
| Shuffle | http://localhost:3001 | `admin@sybsec.local` / `sybsec-shuffle-admin` |

Set the time picker to **Last 24 hours** in Wazuh WUI, Kibana, and Grafana.

**Say:** *"This is sybsec — an open-source SOC built from sensors up to automated
response. Everything you'll see is running live on one host."*

---

## 1. The architecture (1 min, talk only)

**🖥️ Show:** open [`docs/architecture.md`](architecture.md) (the data-flow diagram).

**Say:** *"Seven layers: endpoints and network sensors feed Kafka; Logstash and
Wazuh normalize and detect; a Python ML service scores anomalies; detections
become cases in TheHive and fire SOAR playbooks. Let's walk it bottom-up."*

---

## 2. Endpoints & sensors — the Wazuh agent (1 min)

**▶ Run:**
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

**🖥️ Show:** Wazuh WUI → **Agents**. Point at `sybsec-endpoint-01` = **Active**.

**Say:** *"A Wazuh agent runs on every endpoint — Linux here, Windows in prod via
the MSI — sending file-integrity, auth, and process telemetry to the manager."*

---

## 3. Live attack detection (4 min) — the core

### 3.1 SSH brute force
**▶ Run:**
```bash
./scripts/demo.sh bruteforce       # 12 failed logins, 1s apart
```
**🖥️ Show:** Wazuh WUI → **Threat Hunting / Security events** → filter
`rule.id:100010`. Open the alert.

**Say:** *"Seven atomic failures escalate to Wazuh's built-in brute-force rule,
then our custom rule 100010 confirms it and tags it for SOAR — mapped to MITRE
T1110."*

### 3.2 File Integrity Monitoring
**▶ Run:**
```bash
./scripts/demo.sh fim
```
**🖥️ Show:** Wazuh WUI → **File Integrity Monitoring** → the `passwords.conf`
events (added / modified / deleted) with the **content diff**.

**Say:** *"Real-time FIM catches tampering and shows exactly what changed."*

### 3.3 Web attack / SQL injection
**▶ Run:**
```bash
./scripts/demo.sh webattack
```
**🖥️ Show:** Wazuh WUI → Security events → `rule.id:(31104 OR 31106)`.

**Say:** *"A UNION-SELECT injection is detected — and 31106 means it returned 200,
i.e. it likely worked. MITRE T1190."*

### 3.4 ATT&CK coverage
**🖥️ Show:** Wazuh WUI → **MITRE ATT&CK** module → techniques light up
(Credential Access T1110, Initial Access T1190).

**Say:** *"Every detection is mapped to ATT&CK so we can see coverage and gaps."*

---

## 4. The data pipeline — normalization (2 min)

**Say:** *"Those same alerts don't just live in Wazuh — they're streamed through
Kafka and normalized to a common schema (ECS) in the central store."*

**▶ Run (show the flow with a network alert):**
```bash
./scripts/demo.sh suricata
```
**🖥️ Show:** Kibana → **Discover** → data view **`sybsec security-suricata`**.
Point at ECS fields: `source.ip`, `rule.name`, `event.module`.
Then switch the data view to **`sybsec security-wazuh`** and search
`rule.id:100010` — the same brute-force alert, ECS-normalized.

**Say:** *"Sensor → Kafka → Logstash → Elasticsearch. Everything is one schema,
so detection, ML, and dashboards all speak the same language."*

---

## 5. ML anomaly detection (2 min)

**▶ Run (benign vs malicious):**
```bash
# benign — stays within the learned baseline
curl -s -XPOST localhost:8088/score -H 'Content-Type: application/json' \
  -d '{"event":{"source.ip":"10.0.0.5","destination.port":443,"source.bytes":1200,"event.hour":10,"user.name":"alice"}}'; echo
# malicious — 5GB out, port 4444, 03:00, failed-auth flavor
./scripts/demo.sh anomaly
```
**🖥️ Show:**
- terminal — benign score ≈ 0.17 (`is_anomaly:false`), malicious **1.0**
  with a `reason` and `top_features`.
- Grafana → **ML Anomaly Scores** dashboard (score trend + recent anomalies).
- Kibana → data view **`sybsec security-anomalies`** → the scored doc.

**Say:** *"A PyOD ensemble — Isolation Forest, HBOS, LOF — plus ADTK time-series,
trained on a baseline of normal traffic. It explains *why* something is anomalous,
not just a black-box score."*

---

## 6. Detection → Case automation (2 min) — the payoff

**Say:** *"When a high-severity rule fires, the analyst shouldn't hunt for it —
the case should already exist."*

**▶ Run:**
```bash
./scripts/demo.sh bruteforce       # fires rule 100010 again
```
**🖥️ Show:** TheHive → **Cases** (org **sybsec**). A new case appears:
`[Brute Force / Credential Stuffing] … <source IP>` — severity **HIGH**, tagged
`T1110`, with the agent, source IP, and raw log in the description.

**Say:** *"Wazuh's integrator called our integration which opened this TheHive case
automatically. Cortex would now run reputation analyzers on the source IP."*

---

## 7. SOAR orchestration (1 min)

**🖥️ Show:** Shuffle → **Workflows**. (Open one of the imported playbook JSONs
from `shuffle/playbooks/` if loaded, or show the canvas.)

**Say:** *"Shuffle is the SOAR layer. Playbook 2 for brute force: check AbuseIPDB,
block the IP at the firewall, lock the account, notify the manager. The direct
Wazuh→TheHive path you just saw is the same outcome; Shuffle adds the multi-tool
orchestration and the visual audit trail."*

---

## 8. The finale — one command, whole SOC lights up (1 min)

**▶ Run:**
```bash
./scripts/demo.sh all
```
**🖥️ Show, in ~30s, sweep the tabs:**
1. **Wazuh WUI** — brute force, FIM diff, web attack, sudo all appear.
2. **Kibana** — same events, ECS-normalized.
3. **Grafana** — alert rate + anomaly score tick up.
4. **TheHive** — a fresh case.

**Say:** *"One simulated attack wave — detected on the endpoint, normalized
centrally, scored by ML, mapped to ATT&CK, and turned into a case, in seconds.
That's the full detect-to-respond loop."*

---

## Reset between runs
```bash
./scripts/demo.sh reset            # clears demo logs + FIM files
# (TheHive cases / ES docs persist — delete them in their UIs if you want a clean slate)
```

## If something looks down
```bash
./scripts/demo.sh preflight        # which surface is red?
docker ps --format '{{.Names}}\t{{.Status}}' | grep -iE 'sybsec|wazuh|thehive|shuffle'
```

## What to emphasize vs. what's honest
- **Live & real:** agent telemetry, Wazuh detections + ATT&CK, Kafka→Logstash→ES
  pipeline, ML scoring, Wazuh→TheHive auto-cases, all UIs.
- **Configured, shown as design:** Shuffle visual playbooks (up, not yet bound),
  Cortex analyzers (need real API keys), MISP/OpenCTI threat-intel (next phase),
  production scale (3-node ES / 50k eps — Helm, not this host). See `STATUS.md`.
