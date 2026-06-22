# OpenCTI — ATT&CK correlation

`connectors/` configures two connectors:
- **MITRE ATT&CK** (`connector-mitre`) — imports the enterprise matrix so alerts
  can be mapped to tactics/techniques.
- **MISP** (`connector-misp`) — ingests IoCs from MISP into OpenCTI every 5 min.

TheHive/SOAR query OpenCTI's GraphQL API (Playbook 3) to attach ATT&CK context
to anomaly cases.

## Deploy
OpenCTI **core** (platform + redis + elastic + minio + rabbitmq) is a heavy
stack — deploy it from the official `OpenCTI-Platform/docker` repo, then attach
these connectors:

```bash
docker compose --env-file connectors/connectors.env \
  -f connectors/docker-compose.connectors.yml up -d
```

> Not part of the dev single-box compose (RAM). See `STATUS.md`.
