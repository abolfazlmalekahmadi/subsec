"""Tests for ADTK time-series metric scoring (with MAD fallback)."""
import pandas as pd
import pytest

from models import timeseries


def _series_events(n=48, spike_at=40):
    base = pd.date_range("2026-06-01", periods=n, freq="1h")
    events = []
    for i, ts in enumerate(base):
        value = 100 if i != spike_at else 100000
        events.append({"@timestamp": ts.isoformat(), "value": value, "source.ip": "10.0.0.5"})
    return events


def test_known_metrics_present():
    assert "login_freq_per_user_hour" in timeseries.METRICS
    assert "bytes_per_src_5min" in timeseries.METRICS


def test_score_metric_flags_spike():
    df = pd.DataFrame(_series_events())
    out = timeseries.score_metric(df, "bytes_per_src_5min")
    assert "is_anomaly" in out.columns
    assert out["is_anomaly"].sum() >= 1


def test_unknown_metric_raises():
    df = pd.DataFrame(_series_events())
    with pytest.raises(ValueError):
        timeseries.score_metric(df, "nope")


def test_short_series_flags_nothing():
    s = pd.Series([1.0, 2.0], index=pd.to_datetime(["2026-06-01", "2026-06-02"]))
    flags = timeseries.detect_series(s)
    assert not flags.any()


def test_window_score_in_range():
    df = pd.DataFrame(_series_events())
    out = timeseries.score_metric(df, "bytes_per_src_5min")
    score = timeseries.anomaly_score_from_flags(out["is_anomaly"])
    assert 0.0 <= score <= 1.0
