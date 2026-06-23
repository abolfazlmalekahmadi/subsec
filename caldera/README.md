# MITRE Caldera — continuous red-team validation

`adversaries/weekly-validation.yml` is the sybsec adversary profile that
exercises the four detections in `wazuh/rules/local_rules.xml` (brute force,
malware drop, lateral movement, exfiltration). Each ability is mapped to the
rule it must trigger and an SLA, consumed by the detection-gap loop.

## Deployed & verified (this build)

Caldera was built from source (`git clone --recurse-submodules`) and run:

```bash
git clone --depth 1 --recurse-submodules https://github.com/mitre/caldera.git
cd caldera && sed -i 's/VARIANT: "full"/VARIANT: "slim"/' docker-compose.yml
docker compose up -d --build          # UI at http://localhost:8888
docker logs caldera | grep -A18 "admin credentials"   # red / <generated> + API token
```

A **sandcat agent** was deployed on the Wazuh-monitored endpoint:

```bash
# inside the target host (here: the sybsec wazuh-agent container)
curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux' http://<host-ip>:8888/file/download > sandcat
chmod +x sandcat && ./sandcat -server http://<host-ip>:8888 -group red &
```

Then a custom ability → adversary → operation was run via the API, and the
attack was **detected** end to end:

```
ability "sybsec FIM tamper" (T1565.001) → writes /var/sybsec-watch/...
   → Wazuh FIM rule 554 "File added" fires on agent sybsec-endpoint-01
```

Exported profile: `adversaries/sybsec-redteam-validation.json`. The
detection-gap loop: any ability Wazuh does *not* alert on within SLA becomes a
rule-backlog ticket.

## Atomic Red Team integration

`adversaries/weekly-validation.yml` maps abilities (T1110, T1204, T1021, T1041)
to the rules they must trigger. Caldera runs Atomic tests via the atomic plugin,
so a Sigma/Wazuh rule update can be validated per-technique within minutes.
