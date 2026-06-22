# Build status & honesty ledger

This file tracks what is actually implemented vs. design-only, and records the
hard constraints that prevent the full spec from running on a single host.

## Environment this was built against

- Single host: 16 cores, 62 GB RAM, ~320 GB free disk, Docker 28.5.
- No SPAN port, no second NIC, no Windows endpoints, no AD/LDAP, no pfSense.

## Hard constraints (cannot be satisfied on one box)

| Spec requirement | Reality |
|---|---|
| 3-node Elasticsearch @ 32 GB each | Dev compose runs **1 node**; 3-node is Helm-only |
| 3-broker Kafka @ 16 GB each | Dev compose runs **1 broker** (KRaft) |
| Malcolm @ 32 GB + high-throughput NIC | Not deployed; design + integration notes only |
| 50,000 events/sec sustained | Not testable single-node; load-test harness is design-only |
| pfSense/OPNsense, SPAN mirroring, Sysmon on Windows | Configs provided; **no hardware to deploy/validate** |
| Host isolation in 2 min, Caldera 0-gap, live dashboards | Require real endpoints wired end-to-end |

## Deliverable status

| # | Deliverable | Status |
|---|---|---|
| 1 | `docker-compose.yml` | ⏳ foundation: dev-scale, boots on this box |
| 2 | `kafka/topics.sh` | ✅ implemented |
| 3 | `logstash/pipelines/` | ✅ zeek/suricata/wazuh/sysmon pipelines |
| 4 | `wazuh/rules/local_rules.xml` | ✅ implemented |
| 5 | `wazuh/decoders/local_decoder.xml` | ✅ implemented |
| 6 | `sigma/convert.sh` | ✅ implemented |
| 7 | `yara/update_rules.sh` | ✅ implemented |
| 8 | `ml/anomaly_service/` | ✅ **fully implemented** (FastAPI + PyOD + ADTK + tests) |
| 9 | `shuffle/playbooks/` | ✅ 4 playbook exports (logic complete; app-IDs bound at import) |
| 10 | `misp/setup.sh` | ✅ feed enable + `wazuh/integrations/custom-misp.py` lookup |
| 11 | `opencti/connectors/` | ✅ MITRE + MISP connector compose + env |
| 12 | `thehive/templates/` | ✅ 5 case templates (malware/bruteforce/lateral/exfil/anomaly) |
| 13 | `cortex/analyzers.json` | ✅ VT/AbuseIPDB/Shodan/GeoIP/URLScan/MISP + responders |
| 14 | `dfir-iris/` | ✅ 2 forensic case templates + evidence/custody schema |
| 15 | `grafana/dashboards/` | ✅ 4 dashboards + provisioned datasource |
| 16 | `caldera/adversaries/` | ✅ weekly profile w/ rule→ability detection map |
| 17 | `scripts/deploy.sh` | ✅ implemented (up/down/status/validate/wazuh-certs) |
| 18 | `docs/architecture.md` | ✅ full data-flow + sizing + network model |
| 19 | `docs/runbooks/` | ⏳ brute-force runbook done; 3 more to add |
| 20 | `tests/detection_tests/` | ✅ ML test (runs live) + brute-force test (skips till Wazuh wired) |

**Legend update:** the stubs from the original plan were filled in this pass with
real content. What remains genuinely pending is *live deployment/validation* of
the heavy stacks (MISP, OpenCTI, TheHive/Cortex, Wazuh end-to-end, Malcolm) and
production Helm charts — none runnable on a single 62 GB box. The config/code for
each exists and is version-controlled.

Legend: ✅ done · ⏳ foundation (works, will deepen) · 🧱 stub, planned for next iteration.

## Next iterations (in order)

1. Wire Wazuh profile end-to-end: certs, agent enrolment, Logstash ingest of
   `wazuh-events` from Kafka → make `test_bruteforce.py` pass live.
2. Stand up TheHive + Cortex (own compose); load templates & analyzers; bind
   Shuffle app-IDs and run Playbook 1–4 against synthetic triggers.
3. MISP + OpenCTI cores (heavy, separate hosts); run `misp/setup.sh`, attach
   connectors, enable the Wazuh→MISP lookup; verify rule 100020 escalation.
4. DFIR-IRIS instance + TheHive→IRIS escalation binding.
5. Caldera + Atomic Red Team against real test endpoints; build `gap_check`.
6. Remaining 3 runbooks (malware, lateral movement, exfiltration).
7. Production Helm charts (3-node ES, 3-broker Kafka mTLS, Malcolm, Vault, SSO).

## Verified this build

- ML service: `ruff` clean, **31/31 pytest pass, 89% coverage** (PyOD ensemble
  trained IForest/HBOS/LOF; ADTK time-series ran; FastAPI E2E).
- `docker compose config` valid; all 16 JSON files and YAML parse; all shell
  scripts pass `bash -n` (shellcheck not installed on the build host).

## MVP brought up LIVE on this host (`./scripts/deploy.sh up`)

5 core services healthy: elasticsearch, kibana, kafka, logstash-ready,
ml-anomaly, grafana. Verified end-to-end with real requests:

| Check | Result |
|---|---|
| `GET /health` | ok, detectors=[iforest,hbos,lof], trained_samples=3000 |
| Score **benign** event | 0.17 → `is_anomaly:false` ("within learned baseline") |
| Score **malicious** event (exfil+brute-force) | 1.00 → `is_anomaly:true` + reason |
| ES sink (`sink:true`) | anomaly doc indexed into `security-anomalies` |
| Kafka | 7 topics created; produce→consume round-trip ok |
| Time-series (`/score/timeseries`) | login-freq spike detected (2 anomalous points) |
| Grafana | healthy; `sybsec-es` datasource auto-provisioned to ES |

### Bug found & fixed by the live run (not caught by unit tests)
The cold-start bootstrap trained on `normal(0.3)` noise **in feature space**, so
every real event was out-of-distribution → **everything scored 1.0 (FP storm)**.
Fixed: `models/synthetic.py` now generates realistic benign events (typical
ports, lognormal byte volumes, business-hours bias) through the *real* feature
pipeline. Benign now scores 0.17, malicious 1.0. Unit tests still 31/31.

> AutoEncoder detector is skipped at runtime (no `torch` in the slim image); the
> ensemble runs on IForest+HBOS+LOF and reweights automatically. Add torch to
> `requirements.txt` to enable it.

## Wazuh brought up LIVE (single-node) — `wazuh/single-node/`

Vendored the official Wazuh 4.9 single-node (ports remapped: indexer→9201,
**dashboard/WUI→https://localhost:5602**, login `admin`/`SecretPassword`) with our
`local_rules.xml` + `local_decoder.xml` mounted into the manager.

| Check | Result |
|---|---|
| indexer cluster health | green (1 node) |
| dashboard (WUI) | HTTP 302 on https://localhost:5602 |
| custom rules load | clean (after fixes below) |
| **brute-force detection** | 7× rule 5710 → built-in 5712 → **our 100010 fires** with `sybsec_soar` tag (MITRE T1110) |

### Two more bugs found & fixed by the live run
1. **Rules file failed to load (CRITICAL)** — rule 100030 used a `<field>` regex
   with quad-backslashes, and 100040/100051 used `{n,}`/alternation unsupported
   by OS_Regex. One bad rule blocks the *entire* file. Fixed by switching those
   fields to `type="pcre2"`.
2. **Redundant brute-force rule** — 100010 duplicated Wazuh's built-in 5712 and
   got shadowed. Redesigned to **chain** on the built-in composites
   (`if_sid 5712,5720,5758,5763`) and add the sybsec SOAR hook instead.

Net: the rule fixes are committed to `wazuh/rules/local_rules.xml`, so the repo
version is the corrected, load-clean one.

## Phase 2 LIVE — full pipeline wired & verified

`sensor → Kafka → Logstash(ECS) → Elasticsearch`, and Wazuh alerts forwarded to
the central index.

| Step | Result |
|---|---|
| Logstash live-consuming Kafka | suricata EVE → ECS doc in `security-suricata-*` (source.ip, rule.name, event.module) |
| Wazuh → central ES | new `wazuh/filebeat-forwarder/` tails `alerts.json` → Kafka(wazuh-events) → Logstash → **222 docs in `security-wazuh-*`** incl. our `rule.id:100010` |
| Real Wazuh alerts | brute force `100010` (T1110), FIM `554/550`, web/SQLi `31104/31106` (T1190), sudo `5503` |
| Wazuh indexer | `wazuh-alerts-4.x-*` = 223 docs → WUI modules populate |
| Kibana | data views `sybsec security-{wazuh,suricata,anomalies}` created |
| Grafana | 4 dashboards provisioned + `sybsec-es` datasource live |

Added `restart: unless-stopped` to all core services (Logstash had exited).

## Demo kit (for showing it off)

- `scripts/demo.sh {bruteforce|fim|webattack|sudo|anomaly|suricata|all}` — fires
  **real** detections into the live stack.
- `docs/demo-scenarios.md` — what each scenario triggers and exactly where to
  point in the Wazuh WUI / Kibana / Grafana / ML API, plus a 5-min demo flow.

### Live service map
| UI | URL | Login |
|----|-----|-------|
| Wazuh WUI | https://localhost:5602 | admin / SecretPassword |
| Kibana | http://localhost:5601 | elastic / changeme_elastic |
| Grafana | http://localhost:3000 | admin / changeme_grafana |
| ML API | http://localhost:8088/health | — |
| Elasticsearch | http://localhost:9200 | elastic / changeme_elastic |
