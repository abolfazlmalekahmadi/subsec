# Runbook — Brute force / credential stuffing

**Trigger:** Wazuh rule `100010`/`100011` (≥8 auth failures from one source in
120 s), or Suricata SSH/RDP scan signatures. SOAR **Playbook 2** automates
steps 2–5.

**SLA:** detect < 30 s · contain < 10 min (with SOAR).

## 1. Triage (analyst, ≤2 min)
- Open the TheHive case (auto-created at severity HIGH).
- Confirm the source IP and targeted account(s) in the case observables.
- Check `security-wazuh-*` in Kibana: is it one source→one account (targeted) or
  one source→many accounts (spray)? Filter `rule.id:100010 and source.ip:<ip>`.

## 2. Reputation (auto — Cortex/AbuseIPDB)
- Playbook 2 queries AbuseIPDB. If abuse score > 50 → proceed to containment.
- Manually corroborate with MISP (`misp/` lookup) and OpenCTI for related actor
  infrastructure.

## 3. Contain
- **Auto:** Playbook 2 blocks the IP at pfSense (firewall API) and via Wazuh
  active-response `block-ip.sh` on the targeted host.
- **Account:** if a successful login followed the failures (rule `100012`),
  treat as compromise — lock the account (AD/LDAP), force password reset,
  invalidate sessions.

## 4. Investigate
- Pull all activity from the source IP across `security-*` for the last 24 h.
- For a confirmed successful login: enumerate post-auth actions (Sysmon process
  creation `event.action:process-creation`, new persistence, lateral movement
  rule `100030`). Escalate to the lateral-movement runbook if found.

## 5. Eradicate & recover
- Remove any persistence/created accounts. Restore the account once clean.
- Keep the firewall block until the investigation closes; document in the case.

## 6. Close
- Record MTTD/MTTR (visible in the `mttd_mttr` Grafana dashboard).
- If the rule failed to fire within SLA, file a detection-gap ticket and add an
  Atomic Red Team `T1110` test under `tests/detection_tests/`.

## Validation test
`tests/detection_tests/test_bruteforce.py` (Atomic `T1110`) replays the failure
burst and asserts rule `100010` fires and a case is created within 30 s.
