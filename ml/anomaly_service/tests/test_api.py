"""End-to-end API tests via FastAPI TestClient (no live ES/Kafka needed)."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ML_MODEL_DIR", str(tmp_path))
    # Force a fresh store bootstrap into tmp_path.
    import importlib

    import models.store as store_mod

    importlib.reload(store_mod)
    import main as main_mod

    importlib.reload(main_mod)
    with TestClient(main_mod.app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["fitted"] is True


def test_ready(client):
    assert client.get("/ready").json()["ready"] is True


def test_score_normal_event(client, normal_event):
    r = client.post("/score", json={"event": normal_event})
    assert r.status_code == 200
    body = r.json()
    assert 0.0 <= body["anomaly_score"] <= 1.0
    assert "reason" in body
    assert isinstance(body["top_features"], list)


def test_score_malicious_higher(client, normal_event, malicious_event):
    n = client.post("/score", json={"event": normal_event}).json()["anomaly_score"]
    m = client.post("/score", json={"event": malicious_event}).json()["anomaly_score"]
    assert m >= n


def test_batch_scoring(client, normal_event, malicious_event):
    r = client.post("/score/batch", json={"events": [normal_event, malicious_event]})
    assert r.status_code == 200
    assert r.json()["count"] == 2


def test_timeseries_endpoint(client):
    events = [
        {"@timestamp": f"2026-06-01T{h:02d}:00:00", "value": 100 if h < 20 else 99999}
        for h in range(24)
    ]
    r = client.post(
        "/score/timeseries",
        json={"metric": "login_freq_per_user_hour", "events": events},
    )
    assert r.status_code == 200
    assert "window_score" in r.json()


def test_timeseries_unknown_metric(client):
    r = client.post("/score/timeseries", json={"metric": "x", "events": [{"value": 1}]})
    assert r.status_code == 400


def test_retrain_requires_minimum(client, normal_event):
    r = client.post("/retrain", json={"events": [normal_event] * 10})
    assert r.status_code == 400


def test_retrain_succeeds(client, normal_event):
    r = client.post("/retrain", json={"events": [normal_event] * 60})
    assert r.status_code == 200
    assert r.json()["status"] == "retrained"
