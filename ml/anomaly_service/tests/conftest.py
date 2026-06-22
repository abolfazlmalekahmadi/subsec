"""Shared fixtures. Ensure the service package root is importable as top-level
modules (config, models, api) the same way the app runs it."""
import os
import sys

import numpy as np
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture
def normal_event():
    return {
        "@timestamp": "2026-06-21T10:00:00Z",
        "source.ip": "10.0.0.5",
        "destination.ip": "10.0.0.10",
        "destination.port": 443,
        "network.transport": "tcp",
        "source.bytes": 1200,
        "destination.bytes": 3400,
        "event.duration": 2.1,
        "user.name": "alice",
        "event.severity": 2,
        "event.hour": 10,
    }


@pytest.fixture
def malicious_event():
    # Large exfil-like transfer at an odd hour with a failed-login flavor.
    return {
        "@timestamp": "2026-06-21T03:00:00Z",
        "source.ip": "10.0.0.5",
        "destination.ip": "203.0.113.9",
        "destination.port": 4444,
        "network.transport": "tcp",
        "source.bytes": 5_000_000_000,
        "destination.bytes": 10,
        "event.duration": 0.2,
        "user.name": "svc-backup",
        "event_type": "authentication_failure",
        "rule.id": "5551",
        "event.severity": 12,
        "event.hour": 3,
    }


@pytest.fixture
def fitted_store(tmp_path, monkeypatch):
    """A ModelStore with a small deterministic trained ensemble."""
    monkeypatch.setenv("ML_MODEL_DIR", str(tmp_path))
    from models.store import ModelStore

    s = ModelStore()
    rng = np.random.default_rng(7)
    X = rng.normal(0.3, 0.1, size=(500, 14)).clip(0, 1)
    s.retrain(X)
    return s
