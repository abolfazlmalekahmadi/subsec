# sybsec — Open-Source SOC Platform

An integrated, layered Security Operations Center (SOC) platform: fault &
anomaly detection, attack/intrusion detection, threat-intel correlation,
automated incident response, forensics, and continuous red-team validation.

> **Read [`STATUS.md`](STATUS.md) first.** This repository is built in stages.
> Not every component is deployable on a single host, and several success
> criteria in the original spec require real network hardware and endpoints.
> `STATUS.md` tracks exactly what is implemented, what boots on one box, and
> what is design-only.

## Layered architecture

| Layer | Purpose | Components |
|------:|---------|-----------|
| 0 | Perimeter & traffic mirroring | pfSense/OPNsense, SPAN/AF_PACKET |
| 1 | Collection & sensors | Zeek, Suricata, Snort3, Wazuh agent, Sysmon, Filebeat, Kafka |
| 2 | Storage / index / normalize | Elasticsearch, Logstash, Kibana, Wazuh Manager/Indexer, Graylog |
| 3 | Detection engines | Wazuh rules, Sigma, YARA, Suricata ET; **ML anomaly service**; Malcolm, Grafana |
| 4 | Threat intelligence | MISP, OpenCTI |
| 5 | Case management | TheHive, Cortex, DFIR-IRIS |
| 6 | SOAR & automated response | Shuffle, Wazuh active-response |
| 7 | Red-team validation | MITRE Caldera, Atomic Red Team |

See [`docs/architecture.md`](docs/architecture.md) for the full design,
data flow, sizing, and network/TLS model.

## Repository layout

```
docker-compose.yml        Dev-scale single-node stack (boots on one host)
.env.example              All secrets/config as env vars (copy to .env)
scripts/deploy.sh         End-to-end bring-up with health checks
ml/anomaly_service/       Python/FastAPI ML anomaly microservice (PyOD + ADTK)
kafka/topics.sh           Kafka topic creation
logstash/pipelines/       ECS-normalizing Logstash pipelines per source
wazuh/                    Custom rules, decoders, active-response scripts
sigma/  yara/             Detection-content pull/convert scripts
shuffle/playbooks/        SOAR playbook exports (4)
misp/ opencti/            Threat-intel deploy + connector configs
thehive/ cortex/ dfir-iris/   Case management config & templates
grafana/dashboards/       SOC dashboards (JSON)
caldera/adversaries/      Red-team adversary profiles
docs/                     Architecture + analyst runbooks
tests/detection_tests/    Automated detection-validation tests
```

## Quick start (dev scale)

```bash
cp .env.example .env          # then edit secrets
./scripts/deploy.sh up        # brings up core stack with health checks
./scripts/deploy.sh status    # show health of each service
make ml-test                  # run ML service unit tests
./scripts/deploy.sh down      # tear down
```

> The dev `docker-compose.yml` runs **single-node** Elasticsearch, **one**
> Kafka broker, Wazuh, Suricata, Logstash, Kibana, Grafana, and the ML
> service. Production-scale (3-node ES, 3-broker Kafka, Malcolm) targets
> Kubernetes/Helm — see `STATUS.md`.

## License

Intended for release under Apache-2.0 (see individual upstream component
licenses). This scaffold is provided as-is.
