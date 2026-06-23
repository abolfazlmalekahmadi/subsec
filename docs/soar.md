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

## Shuffle (visual SOAR) — status & how to wire it

Shuffle is **up** (http://localhost:3001, `admin@sybsec.local` /
`sybsec-shuffle-admin`) and the four playbooks are in `shuffle/playbooks/`. The
visual workflow binding is **done in the Shuffle UI** — this Shuffle build does
not provision an API key headlessly (first-run login returns an empty org/user
until the UI setup completes), so the workflow/webhook can't be created purely
from a script. The automated loop above already delivers the same outcome
(block + case); Shuffle adds multi-tool orchestration, approvals, and the visual
audit trail.

### Wire Playbook 2 (brute force) in the UI — ~5 minutes
1. Log into Shuffle → finish first-run (set the org if prompted) →
   **Admin → API key**, copy it.
2. **Workflows → New** → drag a **Webhook** trigger; copy its URL.
3. Add a **TheHive** app node → action *Create case*; set auth =
   `http://sybsec-thehive:9000` + the TheHive API key (org `sybsec`).
4. Add an **HTTP** node → `PUT https://sybsec-wazuh-manager:55000/active-response`
   (or call the blocklist) to block the source IP.
5. (Optional) Add a **Cortex/AbuseIPDB** node before the block for reputation.
6. Save & activate. Then point Wazuh at the webhook by adding an integration to
   the manager config:
   ```xml
   <integration>
     <name>custom-shuffle</name>
     <hook_url>http://<shuffle-host>:3001/api/v1/hooks/<webhook-id></hook_url>
     <rule_id>100010</rule_id>
     <alert_format>json</alert_format>
   </integration>
   ```
7. Fire `./scripts/demo.sh bruteforce` → watch the run light up in Shuffle.

> Import the bundled logic from `shuffle/playbooks/*.json` via
> **Workflows → Import**, then bind each action's app + auth (app IDs are
> environment-specific). See `shuffle/README.md`.
