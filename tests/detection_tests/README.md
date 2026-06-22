# Detection validation tests

End-to-end tests that fire synthetic activity and assert the platform detects
it within SLA. Run against a **live** stack; tests skip (not fail) when the
component they need isn't up, so the suite is honest at any completeness.

```bash
pip install -r requirements.txt
./scripts/deploy.sh up
ELASTIC_PASSWORD=... pytest tests/detection_tests -v
```

| Test | Validates | Needs |
|------|-----------|-------|
| `test_ml_anomaly.py` | malicious event scores ≥ benign; `/health` detectors | ml-anomaly (runs today) |
| `test_bruteforce.py` | auth-failure burst → Wazuh rule 100010 < 30s | Wazuh profile + Logstash ingest (next iter) |

## Detection-gap loop (red-team feedback)

`caldera/adversaries/weekly-validation.yml` maps each Caldera ability to the
Wazuh rule it must trigger and an SLA. A `gap_check` step (next iteration)
queries Elasticsearch after each weekly run; any ability that fired without its
expected alert within SLA auto-creates a TheHive "detection gap" ticket and
appends to the Wazuh rule backlog. Every rule in
`wazuh/rules/local_rules.xml` has a corresponding ability here.
