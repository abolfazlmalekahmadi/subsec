# Shuffle SOAR playbooks

Four production playbooks (`playbooks/`), each an export encoding the trigger →
action → branch logic from the spec:

| File | Trigger | Key actions |
|------|---------|-------------|
| `playbook1_malware.json` | Wazuh 100002 / MISP hash | VT → isolate → case → notify → block hash → memdump |
| `playbook2_bruteforce.json` | Wazuh 100010 | AbuseIPDB → pfSense block → lock account → case → email mgr |
| `playbook3_ml_anomaly.json` | anomaly_score > 0.85 | Wazuh context → OpenCTI ATT&CK → MISP → case → PagerDuty |
| `playbook4_exfiltration.json` | Suricata ET / bytes_out>500MB | block egress → Arkime PCAP → DFIR-IRIS → CRITICAL case |

## Importing

These encode the **logic and parameters**, but Shuffle assigns its own internal
app IDs on import. To use them:

1. Stand up Shuffle, install the apps referenced (`Cortex`, `TheHive`, `Wazuh`,
   `MISP`, `OpenCTI`, `pfSense`, `Arkime`, `PagerDuty`, `Slack`, `Email`).
2. Import each JSON via **Workflows → Import**, then bind each action's app to
   the installed app version and fill the authentication fields (all read from
   env: `$VIRUSTOTAL_API_KEY`, `$PFSENSE_API_KEY`, `$SLACK_WEBHOOK`, etc.).
3. Point the webhook triggers at the Wazuh `integratord` / ml-anomaly webhooks.

> Status: logic complete; app-ID binding is environment-specific and done at
> import time. Tracked in `STATUS.md`.
