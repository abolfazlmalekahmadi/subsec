# MITRE Caldera — continuous red-team validation

`adversaries/weekly-validation.yml` is the sybsec adversary profile that
exercises the four detections in `wazuh/rules/local_rules.xml` (brute force,
malware drop, lateral movement, exfiltration). Each ability is mapped to the
rule it must trigger and an SLA, consumed by the detection-gap loop.

## Deploy & schedule

```bash
# Run Caldera server (official image) and register your test endpoints as agents.
docker run -d --name caldera -p 8888:8888 mitre/caldera:latest
# Import the profile, then schedule a weekly operation against the 'test' group:
#   Operations → New → adversary "sybsec Weekly Validation" → group "test" → schedule weekly
```

## Atomic Red Team integration

The ability IDs reference Atomic Red Team tests (T1110, T1204, T1021, T1041).
Caldera runs them via the Atomic plugin as an ability library, so a Sigma/Wazuh
rule update can be validated per-technique within minutes.

> Status: profile + detection mapping defined. Live scheduling needs real test
> endpoints (none in this environment). See `STATUS.md`.
