#!/var/ossec/framework/python/bin/python3
"""Wazuh -> TheHive integration.

Wazuh's integratord calls this with (alert_file, api_key, hook_url, options)
whenever an alert matches the <integration> rule filter in ossec.conf. We map
the alert to a TheHive case (severity by rule level, template by rule group) so
high-severity sybsec detections automatically open an investigation.

Install: copy this + the `custom-thehive` wrapper into /var/ossec/integrations/,
chmod 750, owned by root:wazuh, then add an <integration> block (see
wazuh/integrations/README or STATUS.md).
"""
import json
import sys
import urllib.request

# Map Wazuh rule.level (0-15) -> TheHive severity (1 low .. 4 critical).
def _severity(level: int) -> int:
    if level >= 13:
        return 4
    if level >= 10:
        return 3
    if level >= 7:
        return 2
    return 1


# Pick a case template/title prefix from rule groups.
def _classify(groups):
    g = set(groups or [])
    if {"bruteforce", "authentication_failures"} & g:
        return "Brute Force / Credential Stuffing", ["bruteforce", "T1110"]
    if "malware" in g:
        return "Malware Detection", ["malware", "T1204"]
    if "exfiltration" in g:
        return "Data Exfiltration", ["exfiltration", "T1041"]
    if "lateral_movement" in g:
        return "Lateral Movement", ["lateral-movement", "T1021"]
    if "ml_anomaly" in g:
        return "Anomalous Behavior (ML)", ["ml-anomaly"]
    return "Security Alert", ["sybsec"]


def main():
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as fh:
        alert = json.load(fh)

    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))
    desc = rule.get("description", "Wazuh alert")
    groups = rule.get("groups", [])
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    kind, tags = _classify(groups)
    srcip = data.get("srcip", "")

    case = {
        "title": f"[{kind}] {desc}",
        "description": (
            f"**Auto-created by Wazuh rule {rule.get('id')}** (level {level})\n\n"
            f"- Agent: {agent.get('name')} ({agent.get('ip')})\n"
            f"- Source IP: {srcip or 'n/a'}\n"
            f"- MITRE: {', '.join(rule.get('mitre', {}).get('id', []) or [])}\n\n"
            f"```\n{alert.get('full_log','')[:500]}\n```"
        ),
        "severity": _severity(level),
        "tags": ["sybsec", "wazuh", f"rule:{rule.get('id')}"] + tags,
        "flag": False,
        "tlp": 2,
        "pap": 2,
    }

    req = urllib.request.Request(
        f"{hook_url}/api/v1/case",
        data=json.dumps(case).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.load(r)
        sys.stderr.write(f"thehive: created case {res.get('number')} ({res.get('_id')})\n")
    except Exception as exc:
        sys.stderr.write(f"thehive: case creation failed: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
