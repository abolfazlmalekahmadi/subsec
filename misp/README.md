# MISP — threat intelligence

- `setup.sh` — enables the default community feeds (CIRCL, Abuse.ch, OTX),
  creates the automation flow, and triggers an initial fetch. Needs `MISP_URL`
  and an admin `MISP_API_KEY`.
- `../wazuh/integrations/custom-misp.py` — the Wazuh→MISP lookup. Every Wazuh
  alert carrying an IP/hash/domain queries MISP; a match writes a
  `threat_intel.misp` field back into Wazuh, which rule `100020` escalates to
  CRITICAL.

## Deploy
MISP runs from its official compose (`MISP/misp-docker`); it is **not** part of
the dev single-box stack (heavy). After it's up:

```bash
MISP_URL=https://misp.local MISP_API_KEY=<admin-key> ./misp/setup.sh
# then enable the Wazuh integration block (see custom-misp.py docstring)
```

OpenCTI ingests from MISP via the MISP connector (`../opencti/connectors/`).

> Status: scripts complete; live MISP deploy + feed sync is a follow-up. See
> `STATUS.md`.
