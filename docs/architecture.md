# sybsec architecture

Open-source, layered SOC platform: detect (fault / anomaly / intrusion),
correlate (threat intel), respond (SOAR), investigate (forensics), and
continuously validate (red team).

## 1. Data flow

```
                            LAYER 0  PERIMETER
                   pfSense / OPNsense  ──(SPAN / AF_PACKET mirror)──┐
                                                                    │
   LAYER 1  SENSORS                                                 ▼
   ┌──────────┐  ┌───────────┐  ┌─────────┐  ┌──────────────┐  ┌──────────┐
   │   Zeek   │  │ Suricata  │  │ Snort3  │  │ Wazuh agent  │  │  Sysmon  │
   │ conn/dns │  │ EVE JSON  │  │  IPS    │  │ FIM/auditd/  │  │ (Windows)│
   │ ssl/http │  │  alerts   │  │         │  │ winevt/auth  │  │          │
   └────┬─────┘  └─────┬─────┘  └────┬────┘  └──────┬───────┘  └────┬─────┘
        │              │             │              │               │
        └──────────────┴──── Filebeat / Winlogbeat ─┴───────────────┘
                                     │  (one topic per source)
                                     ▼
                          ┌─────────────────────┐
                          │       KAFKA          │  zeek-logs / suricata-alerts
                          │  (KRaft, mTLS prod)  │  wazuh-events / sysmon-events
                          └──────────┬───────────┘
              ┌──────────────────────┼───────────────────────┐
              ▼                      ▼                        ▼
   LAYER 2  ┌──────────┐    LAYER 3B ┌──────────────┐   ┌──────────────┐
   NORMALIZE│ Logstash │   ML ANOMALY│  ml-anomaly  │   │ Wazuh Manager│ LAYER 2/3A
   (ECS)    │ pipelines│   (FastAPI) │ PyOD + ADTK  │   │ rules/decoders│ rule engine
            └────┬─────┘             └──────┬───────┘   │ Sigma + YARA │
                 │                          │           └──────┬───────┘
                 ▼                          ▼                  │
          ┌───────────────────────────────────────────────────┘
          ▼
   ┌──────────────────┐   security-* indices (ILM: hot→warm→cold→delete)
   │  Elasticsearch   │◄──────────── security-anomalies (ML sink)
   │   (Kibana UI)    │
   └─────┬───────┬────┘
         │       │
   LAYER 3C      │            LAYER 4  THREAT INTEL
   ┌────────┐    │            ┌────────┐   ┌──────────┐
   │Grafana │    │            │  MISP  │◄─▶│ OpenCTI  │  ATT&CK mapping
   │ MTTD/  │    │            │ feeds  │   │ (GraphQL)│
   │ MTTR   │    │            └───┬────┘   └────┬─────┘
   └────────┘    │                │             │
                 ▼                ▼             ▼
   LAYER 6  ┌─────────────────────────────────────────┐
   SOAR     │            Shuffle SOAR                  │  4 playbooks
            │  (Wazuh/MISP/anomaly/Suricata triggers)  │
            └───────────┬─────────────────┬───────────┘
                        ▼                 ▼
   LAYER 5  ┌────────────────┐   ┌──────────────────┐
   CASES    │    TheHive     │──▶│   DFIR-IRIS      │  forensic depth
            │  + Cortex      │   │  PCAP / timeline │  chain of custody
            │  (analyzers)   │   └──────────────────┘
            └────────────────┘
                        ▲
   LAYER 7  ┌────────────────┐
   RED TEAM │ MITRE Caldera  │  weekly runs → detection-gap tickets → Wazuh backlog
            │ + Atomic RT    │
            └────────────────┘
```

## 2. Component responsibilities

| Layer | Component | Role | This repo |
|------:|-----------|------|-----------|
| 0 | pfSense/OPNsense | Routing, FW, port mirror to sensors | design only (no HW) |
| 1 | Zeek | Network metadata (conn/dns/ssl/http/files) | `zeek/`, `filebeat/` |
| 1 | Suricata | IDS/IPS, EVE JSON, file extraction | `suricata/` ✅ |
| 1 | Snort3 | Secondary IPS validation | design only |
| 1 | Wazuh agent | FIM, auditd, winevt, auth logs | `wazuh/` |
| 1 | Sysmon | Windows process/net/registry telemetry | `logstash/.../sysmon.conf` |
| 1 | Filebeat/Kafka | Reliable transport, one topic/source | `filebeat/`, `kafka/` ✅ |
| 2 | Elasticsearch/Kibana | Index + explore, ILM | compose ✅ |
| 2 | Logstash | ECS normalization | `logstash/pipelines/` ✅ |
| 2 | Wazuh Mgr/Indexer | Rule engine, decoders, FIM alerting | `wazuh/`, compose (profile) |
| 3A | Sigma / YARA | Community detections | `sigma/`, `yara/` ✅ |
| 3B | ml-anomaly | PyOD ensemble + ADTK time series | `ml/anomaly_service/` ✅ |
| 3C | Grafana / Malcolm | Metrics, full PCAP forensics | `grafana/` (stub) |
| 4 | MISP / OpenCTI | IoC feeds, ATT&CK correlation | `misp/`, `opencti/` (stub) |
| 5 | TheHive / Cortex / IRIS | Cases, analyzers, forensics | `thehive/`, `cortex/`, `dfir-iris/` (stub) |
| 6 | Shuffle | SOAR playbooks, active response | `shuffle/`, `wazuh/active-response/` |
| 7 | Caldera / Atomic RT | Red-team validation, gap loop | `caldera/`, `tests/` (stub) |

✅ = implemented in this foundation. See `STATUS.md` for the full ledger.

## 3. The ML anomaly service (Layer 3B)

The only component that is bespoke code rather than configuration. Implemented
and tested (`ml/anomaly_service/`, 89% coverage).

- **Features** (`models/features.py`): a fixed 14-dim vector extracted from any
  of the four source schemas (Zeek/Suricata/Wazuh/Sysmon). Categorical fields
  are hashed into a bounded space so the dimensionality is stable across unseen
  values; missing fields default safely. Training and inference always agree on
  ordering.
- **Ensemble** (`models/ensemble.py`): PyOD `IForest + AutoEncoder + HBOS + LOF`,
  each calibrated to a probability and combined by normalized weighted average.
  Degrades gracefully if a heavy detector (AutoEncoder/torch) is unavailable.
- **Time series** (`models/timeseries.py`): ADTK `PersistAD + QuantileAD` over
  login-freq, bytes-per-source, process-spawn-rate, failed-auth-rate, with a
  MAD fallback.
- **Serving** (`main.py`, `api/`): `POST /score` → `{anomaly_score, reason,
  top_features, per_model}`; `/score/batch`, `/score/timeseries`, `/retrain`,
  `/health`. Anomalies (score ≥ threshold, default 0.85) are pushed to the
  `security-anomalies` index and, via the Kafka consumer, drive SOAR Playbook 3.
- **Lifecycle** (`models/store.py`): bootstraps a synthetic baseline on first
  start (flagged in `/health`), persists the trained ensemble to disk, and
  retrains weekly on a rolling 30-day window.

## 4. Detection → response correlation

1. Sensor emits event → Kafka → (Logstash→ES) and (Wazuh rules) and (ml-anomaly).
2. A rule/anomaly fires → enriched with MISP IoC match + OpenCTI ATT&CK context.
3. Shuffle trigger evaluates → runs Cortex analyzers, takes active-response
   action (block IP / isolate host / kill process), opens a TheHive case.
4. High-severity / forensic cases escalate to DFIR-IRIS with PCAP + timeline.
5. Caldera weekly run replays ATT&CK techniques; any technique not detected
   becomes a TheHive "detection gap" ticket feeding the Wazuh rule backlog.

## 5. Production topology (Kubernetes / Helm — not in dev compose)

| Component | Sizing (per spec) | Notes |
|-----------|-------------------|-------|
| Elasticsearch | 3 nodes × 32 GB RAM, NVMe (hot) + SAS (warm) | dev = 1 node |
| Kafka | 3 brokers × 16 GB, mTLS between brokers/consumers | dev = 1 KRaft broker |
| Wazuh Manager | 16 GB / 8 vCPU, port 1514 agents-only | profile in dev compose |
| Malcolm | 32 GB, high-throughput NIC, Arkime full PCAP | not deployed |
| Cold storage | MinIO / S3 (30–90 days) | ILM `cold`/`delete` |

### Networking / security model
- TLS 1.3 inter-service; mTLS Kafka brokers↔consumers.
- Secrets via HashiCorp Vault or Docker/K8s secrets — never in images.
- VLAN segmentation: sensor / management / storage.
- Nginx reverse proxy + Keycloak SSO in front of TheHive/Cortex/Kibana/Grafana.
- Elasticsearch and Wazuh manager never exposed to the internet.

### Retention
- Hot 0–7 d (NVMe) → Warm 7–30 d (SAS) → Cold 30–90 d (object) → delete.
- PCAP: 7-day rolling. Logs: ≥90 days (compliance). ILM policy `sybsec-ilm`
  is applied by `scripts/deploy.sh`.

## 6. Honest limitations

See `STATUS.md`. In short: a single host cannot run the full production
topology nor sustain 50k events/sec, and Layer-0/endpoint components need real
network hardware. The dev compose validates the seams that *can* be exercised on
one box; production numbers are design targets to be measured on real infra.
