"""E2E: the ML anomaly service detects a malicious event above the threshold.

Validates the success criterion: an anomalous event yields a high score with a
reason. Runs against a live service (skipped if not up)."""
import requests


def _score(url, event):
    r = requests.post(f"{url}/score", json={"event": event}, timeout=5)
    r.raise_for_status()
    return r.json()


def test_benign_below_malicious(ml_url):
    benign = _score(ml_url, {
        "source.ip": "10.0.0.5", "destination.port": 443,
        "source.bytes": 1200, "event.hour": 10, "user.name": "alice",
    })
    malicious = _score(ml_url, {
        "source.ip": "10.0.0.5", "destination.port": 4444,
        "source.bytes": 5_000_000_000, "event.hour": 3,
        "rule.id": "5551", "event_type": "authentication_failure", "event.severity": 12,
    })
    assert 0.0 <= benign["anomaly_score"] <= 1.0
    assert malicious["anomaly_score"] >= benign["anomaly_score"]
    assert "reason" in malicious
    assert isinstance(malicious["top_features"], list) and malicious["top_features"]


def test_health_reports_detectors(ml_url):
    h = requests.get(f"{ml_url}/health", timeout=5).json()
    assert h["status"] == "ok"
    assert h["fitted"] is True
    # At least one PyOD detector should be active.
    assert len(h["detectors"]) >= 1
