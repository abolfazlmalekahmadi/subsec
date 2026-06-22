"""Synthetic *benign* baseline generator.

The bootstrap model must be trained on data whose feature distribution matches
real traffic — otherwise every real event is an out-of-distribution outlier and
the service flags everything (a false-positive storm). Rather than sample noise
in feature space, we synthesize plausible benign security events and run them
through the SAME `extract_features` pipeline used at inference. The detectors
then learn the real manifold (typical ports, byte volumes, business hours, no
auth failures), so a normal event scores low and an exfil/brute-force event
scores high.

This is only a cold-start baseline; `/retrain` replaces it with a real rolling
30-day window as soon as production data is available.
"""
from __future__ import annotations

import numpy as np

from .features import extract_features

# Realistic benign mix.
_COMMON_PORTS = [443, 443, 443, 80, 80, 53, 22, 3306, 8080, 123]
_PROTOS = ["tcp", "tcp", "tcp", "udp"]
_USERS = ["alice", "bob", "carol", "dave", "svc-app", "svc-web", "eve", "frank"]
_HOSTS = ["web01", "web02", "app01", "db01", "wks-12", "wks-07"]


def _benign_event(rng: np.random.Generator) -> dict:
    # Byte volumes: lognormal, typically a few hundred bytes to ~a few MB.
    src_bytes = float(rng.lognormal(mean=7.0, sigma=1.4))      # ~1KB median
    dst_bytes = float(rng.lognormal(mean=7.5, sigma=1.6))
    # Business-hours-weighted hour-of-day.
    hour = int(rng.choice(range(24), p=_hour_weights()))
    return {
        "@timestamp": "2026-06-21T00:00:00Z",
        "source.ip": f"10.0.{rng.integers(0, 4)}.{rng.integers(1, 254)}",
        "destination.ip": f"10.0.{rng.integers(0, 8)}.{rng.integers(1, 254)}",
        "destination.port": int(rng.choice(_COMMON_PORTS)),
        "network.transport": str(rng.choice(_PROTOS)),
        "network.direction": "outbound" if rng.random() < 0.7 else "inbound",
        "source.bytes": src_bytes,
        "destination.bytes": dst_bytes,
        "event.duration": float(abs(rng.normal(2.0, 3.0))),
        "user.name": str(rng.choice(_USERS)),
        "host.name": str(rng.choice(_HOSTS)),
        "event.severity": int(rng.choice([0, 1, 2, 3], p=[0.55, 0.25, 0.15, 0.05])),
        "event.hour": hour,
    }


def _hour_weights() -> np.ndarray:
    # Higher weight 8:00–18:00, lower overnight.
    base = np.array([0.2] * 24, dtype=float)
    for h in range(8, 19):
        base[h] = 1.0
    for h in (7, 19, 20):
        base[h] = 0.6
    return base / base.sum()


def benign_baseline(n: int = 3000, seed: int = 42) -> np.ndarray:
    """Return an (n, FEATURE_DIM) matrix of featurized benign events."""
    rng = np.random.default_rng(seed)
    return np.array([extract_features(_benign_event(rng)) for _ in range(n)])
