"""Feature extraction: turn a heterogeneous security event (Zeek/Suricata/
Wazuh/Sysmon, normalized to ECS-ish keys) into a stable numeric vector.

The feature space is intentionally fixed and ordered (FEATURE_NAMES) so that
training and inference always agree, even when an event is missing fields.
Missing values map to 0.0; categorical fields are hashed into a bounded space
to keep the vector dense and dimensionally stable across unseen categories.
"""
from __future__ import annotations

import hashlib
import math
from typing import Any

# Fixed, ordered feature space. Do not reorder — model artifacts depend on it.
FEATURE_NAMES: list[str] = [
    "log_bytes",            # log1p(network/source bytes)
    "log_dest_bytes",      # log1p(destination bytes)
    "duration",            # connection duration (s)
    "dest_port",           # destination port (normalized)
    "proto_hash",          # hashed network protocol
    "event_severity",      # 0-15 normalized
    "hour_sin",            # cyclic hour-of-day
    "hour_cos",
    "is_inbound",          # 0/1 direction
    "failed_login_flag",   # 0/1
    "process_spawn",       # 0/1 (sysmon EID 1 etc.)
    "src_ip_hash",         # hashed source ip (locality bucket)
    "user_hash",           # hashed username
    "bytes_ratio",         # out/(in+1) ratio, clipped
]

FEATURE_DIM = len(FEATURE_NAMES)
_HASH_BUCKETS = 997  # bound categorical hashing into [0,1)


def _hash_unit(value: Any, buckets: int = _HASH_BUCKETS) -> float:
    """Stable hash of a value into the unit interval [0, 1)."""
    if value is None:
        return 0.0
    digest = hashlib.blake2b(str(value).encode("utf-8"), digest_size=8).digest()
    return (int.from_bytes(digest, "big") % buckets) / buckets


def _num(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _get(event: dict, *keys: str, default: Any = None) -> Any:
    """First non-null value across candidate dotted/flat keys."""
    for key in keys:
        if key in event and event[key] is not None:
            return event[key]
        # shallow dotted lookup
        if "." in key:
            cur: Any = event
            ok = True
            for part in key.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok and cur is not None:
                return cur
    return default


def extract_features(event: dict) -> list[float]:
    """Map a single event dict to the fixed-length feature vector.

    Robust to missing fields and to the differing schemas of Zeek conn.log,
    Suricata EVE, Wazuh alerts, and Sysmon events.
    """
    src_bytes = _num(_get(event, "source.bytes", "orig_bytes", "bytes_in", "data"))
    dst_bytes = _num(_get(event, "destination.bytes", "resp_bytes", "bytes_out"))
    duration = _num(_get(event, "event.duration", "duration"))
    dest_port = _num(_get(event, "destination.port", "dest_port", "id.resp_p"))
    proto = _get(event, "network.transport", "proto", "app_proto", default="unknown")
    severity = _num(_get(event, "event.severity", "rule.level", "alert.severity", "level"))
    hour = _num(_get(event, "event.hour", "hour"), default=0.0) % 24

    direction = _get(event, "network.direction", "direction", default="")
    is_inbound = 1.0 if str(direction).lower() in {"inbound", "ingress", "in"} else 0.0

    rule_id = str(_get(event, "rule.id", "rule_id", default=""))
    event_type = str(_get(event, "event_type", "event.action", default="")).lower()
    failed_login = 1.0 if (
        "fail" in event_type or rule_id in {"5551", "5710", "5716", "5760"}
    ) else 0.0

    sysmon_eid = str(_get(event, "winlog.event_id", "event_id", default=""))
    process_spawn = 1.0 if sysmon_eid in {"1", "4688"} else 0.0

    src_ip = _get(event, "source.ip", "src_ip", "id.orig_h")
    user = _get(event, "user.name", "user", "username", "srcuser")

    bytes_ratio = min(dst_bytes / (src_bytes + 1.0), 1e6)

    return [
        math.log1p(max(src_bytes, 0.0)),
        math.log1p(max(dst_bytes, 0.0)),
        min(duration, 86400.0),
        min(dest_port / 65535.0, 1.0),
        _hash_unit(proto),
        min(severity / 15.0, 1.0),
        math.sin(2 * math.pi * hour / 24.0),
        math.cos(2 * math.pi * hour / 24.0),
        is_inbound,
        failed_login,
        process_spawn,
        _hash_unit(src_ip),
        _hash_unit(user),
        math.log1p(bytes_ratio),
    ]


def explain(event: dict, vector: list[float]) -> dict[str, float]:
    """Human-readable mapping of feature name -> value for alert context."""
    return dict(zip(FEATURE_NAMES, vector, strict=True))
