# Wazuh integrations

Scripts that Wazuh's `integratord` invokes when an alert matches an
`<integration>` block in the manager config.

| Script | Trigger | Action |
|--------|---------|--------|
| `custom-thehive` / `.py` | rules `100002,100010,100011,100040,100051` | create a TheHive case (severity by rule level, template by group) |
| `custom-misp.py` | any alert with IP/hash/domain | MISP IoC lookup → enrich + escalate (rule 100020) |

## Wazuh → TheHive (verified live)

Chain: **detection → case**.

```
SSH brute force → rule 5710 → 5712 → 100010 (sybsec)
  → integratord → custom-thehive.py → POST /api/v1/case → TheHive case (HIGH)
```

### Install (single-node)
```bash
# 1) make TheHive reachable from the manager
docker network connect single-node_default sybsec-thehive

# 2) install the scripts into the manager
docker cp wazuh/integrations/custom-thehive.py single-node-wazuh.manager-1:/var/ossec/integrations/
docker cp wazuh/integrations/custom-thehive    single-node-wazuh.manager-1:/var/ossec/integrations/
docker exec single-node-wazuh.manager-1 sh -c \
  'chown root:wazuh /var/ossec/integrations/custom-thehive*; chmod 750 /var/ossec/integrations/custom-thehive*'

# 3) add the <integration> block to wazuh_manager.conf (see that file) and set
#    a real org service-user API key in place of __THEHIVE_API_KEY__
# 4) restart the manager
```

### Get a TheHive API key
```bash
TH=http://localhost:9000; ADMIN='admin@thehive.local:secret'
curl -s -u "$ADMIN" -XPOST $TH/api/v1/organisation -d '{"name":"sybsec","description":"SOC"}'
curl -s -u "$ADMIN" -XPOST $TH/api/v1/user \
  -d '{"login":"soc-bot@sybsec.local","name":"SOC Automation","organisation":"sybsec","profile":"org-admin"}'
curl -s -u "$ADMIN" -XPOST $TH/api/v1/user/soc-bot@sybsec.local/key/renew    # -> API key
```

> **Secret hygiene:** the committed `wazuh_manager.conf` ships `__THEHIVE_API_KEY__`
> as a placeholder. The real key is injected only into the running container —
> never commit it.

## SOAR options

Two ways to drive response from a Wazuh alert:
1. **Direct** (this integration) — Wazuh → TheHive. Simplest, proven.
2. **Via Shuffle** (`shuffle/`) — Wazuh → Shuffle webhook → Cortex analyzers →
   TheHive case + active response. Richer orchestration; see `shuffle/README.md`.
