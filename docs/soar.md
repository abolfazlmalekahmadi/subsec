# SOAR & automated response

## What's LIVE and verified

A confirmed brute force triggers a **fully automated detect → respond loop** with
no analyst action:

```
SSH brute force → Wazuh rule 5710 → 5712 → 100010 (sybsec, MITRE T1110)
   ├─ active-response  sybsec-blocklist  → source IP added to the firewall blocklist
   └─ integration      custom-thehive    → TheHive case opened (severity HIGH)
```

Verified end-to-end (`192.0.2.99` → blocklist entry + new case). Orchestrated by
Wazuh's active-response + integrator engine.

- **Block:** `wazuh/active-response/sybsec-blocklist.sh` appends the IP to
  `/var/ossec/etc/lists/sybsec-blocklist` (a pfSense/iptables-alias stand-in that
  this single-host demo can verify without `NET_ADMIN`; in production the AR is
  swapped for `firewall-drop` or a pfSense API call). See it with
  `./scripts/demo.sh blocklist`.
- **Case:** `wazuh/integrations/custom-thehive.py` POSTs to TheHive.
- Both the `<active-response>` and `<integration>` blocks live in the **mounted**
  manager config (`wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf`) so
  they survive restarts. The TheHive API key is the only secret — it ships as the
  `__THEHIVE_API_KEY__` placeholder and is injected at deploy time by
  `scripts/deploy-all.sh` (never committed).

## Shuffle (visual SOAR) — WIRED & verified (4-node pipeline)

The brute-force path runs through a real multi-stage Shuffle workflow, verified
end to end against live attacks:

```
SSH brute force → Wazuh 100010 → (shuffle integration) → Shuffle webhook
   → PB2 — Brute Force Response
        1. geoip   (HTTP GET ip-api.com)      → country / city / ISP / ASN of the attacker
        2. block   (HTTP POST firewall-api)   → source IP added to the blocklist
        3. case    (HTTP POST TheHive)        → enriched [SOAR] case (geo + block status)
        4. notify  (Shuffle Tools)            → SOC summary line
```

Verified live (`45.33.32.156`): Shuffle execution with all 4 nodes SUCCESS,
firewall-api block, and a `[SOAR]` TheHive case titled with the attacker's
country. Runs are visible in the Shuffle UI (Workflows → PB2 → Executions) —
click any node to see its input/output.

- **firewall-api** (`services/firewall-api/`, host `:8099`) is the block target —
  a pfSense/iptables-alias stand-in the demo can verify (`GET /blocklist`).
- Workflow export: `shuffle/playbooks/pb2_bruteforce_shuffle.json` (sanitized —
  `__THEHIVE_API_KEY__` / `__HOST_IP__` placeholders).
- Reproduce the wiring with `./scripts/wire-shuffle.sh <SHUFFLE_APIKEY>` (imports
  the workflow, creates+starts the webhook, joins the Shuffle network, registers
  the Wazuh `shuffle` integration).
- GeoIP uses the free no-key `ip-api.com`; swap in Cortex/AbuseIPDB for richer
  reputation by adding a node before `case`.

### Why a few values are environment-specific
- **Shuffle API key** — this Shuffle build requires a ≥36-char (UUID) key and
  doesn't provision one headlessly; generate it once in the UI
  (avatar → **Settings → API key → regenerate**) and pass it to the script.
- **Webhook id** — created per-deployment; injected into the manager config in
  place of `__SHUFFLE_WEBHOOK_ID__`.
- **Host IP** — Shuffle runs app containers in a swarm overlay, so the HTTP node
  reaches TheHive via the host IP (`__HOST_IP__:9000`), not the container name.

### Extending the workflow (in the UI)
Open PB2 and add nodes before the case: a **Cortex/AbuseIPDB** reputation check,
then an **HTTP** node to block the IP (call the Wazuh API active-response or a
pfSense alias). The bundled `shuffle/playbooks/playbook{1,3,4}*.json` describe
the other three playbooks' logic to build the same way.

> Note: the direct Wazuh→TheHive integration (`custom-thehive`) and this Shuffle
> path both run, so a brute force currently opens two cases (`[Brute Force …]`
> and `[SOAR] …`). In production pick one path; disable `custom-thehive` if
> Shuffle owns case creation.
