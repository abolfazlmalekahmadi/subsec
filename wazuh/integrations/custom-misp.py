#!/usr/bin/env python3
"""Wazuh -> MISP integration.

Wazuh's integrator invokes this with (alert_file, api_key, hook_url). For every
alert carrying an IP, file hash, or domain, we query MISP; on a match we write
an enriched event back into Wazuh (queue socket) tagged so rule 100020 escalates
the alert to CRITICAL.

Configure in ossec.conf:
    <integration>
      <name>custom-misp</name>
      <hook_url>https://misp.local</hook_url>
      <api_key>${MISP_API_KEY}</api_key>
      <alert_format>json</alert_format>
    </integration>
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import sys
import urllib.request

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"


def _iter_iocs(alert: dict):
    data = alert.get("data", {})
    for key in ("srcip", "dstip"):
        v = data.get(key)
        if v:
            try:
                ipaddress.ip_address(v)
                yield ("ip-dst", v)
            except ValueError:
                pass
    for key in ("sha256", "sha1", "md5"):
        v = data.get(key) or (data.get("osquery", {}) or {}).get(key)
        if v:
            yield (key, v)
    dom = data.get("domain") or (data.get("dns", {}) or {}).get("query")
    if dom:
        yield ("domain", dom)


def misp_lookup(base_url: str, api_key: str, value: str) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps({"value": value, "limit": 1}).encode()
    req = urllib.request.Request(
        f"{base_url}/attributes/restSearch",
        data=body,
        headers={"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            res = json.load(r)
        attrs = res.get("response", {}).get("Attribute", [])
        return attrs[0] if attrs else None
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"misp lookup failed: {exc}\n")
        return None


def send_to_wazuh(payload: dict) -> None:
    msg = f"1:misp:{json.dumps(payload)}"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(SOCKET_ADDR)
    s.send(msg.encode())
    s.close()


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write("usage: custom-misp.py <alert_file> <api_key> <hook_url>\n")
        return 1
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as fh:
        alert = json.load(fh)

    for ioc_type, value in _iter_iocs(alert):
        hit = misp_lookup(hook_url, api_key, value)
        if hit:
            send_to_wazuh(
                {
                    "threat_intel": {
                        "misp": {
                            "matched": True,
                            "type": ioc_type,
                            "value": value,
                            "event_id": hit.get("event_id"),
                            "category": hit.get("category"),
                            "to_ids": hit.get("to_ids"),
                        }
                    },
                    "original_rule": alert.get("rule", {}).get("id"),
                }
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
