"""ADTK-based time-series anomaly detection.

Detects anomalies on per-entity time series:

  * Login frequency per user per hour
  * Bytes transferred per source IP per 5-min window
  * Process spawn rate per endpoint
  * Failed authentication rate per service

Each metric is fed as a pandas Series (datetime index -> value). We use ADTK's
combination of a PersistAD (sudden change vs. recent history) and a
QuantileAD / threshold detector (absolute level). If ADTK is unavailable, a
robust median-absolute-deviation (MAD) fallback keeps the API working.
"""
from __future__ import annotations

import logging

import numpy as np
import pandas as pd

log = logging.getLogger("ml.timeseries")

try:  # pragma: no cover - import wiring
    from adtk.data import validate_series
    from adtk.detector import PersistAD, QuantileAD

    _ADTK = True
except Exception as exc:  # pragma: no cover
    log.warning("ADTK unavailable, using MAD fallback: %s", exc)
    _ADTK = False


# Metric definitions: name -> (resample rule, description)
METRICS: dict[str, dict] = {
    "login_freq_per_user_hour": {"rule": "1h", "by": "user.name"},
    "bytes_per_src_5min": {"rule": "5min", "by": "source.ip"},
    "process_spawn_per_host": {"rule": "5min", "by": "host.name"},
    "failed_auth_per_service": {"rule": "1h", "by": "service.name"},
}


def _mad_anomalies(series: pd.Series, threshold: float = 3.5) -> pd.Series:
    """Median-absolute-deviation outlier flags (fallback)."""
    med = series.median()
    mad = (series - med).abs().median() + 1e-9
    modified_z = 0.6745 * (series - med) / mad
    return (modified_z.abs() > threshold)


def detect_series(series: pd.Series, c: float = 3.0) -> pd.Series:
    """Return a boolean Series flagging anomalous timestamps.

    `series` must have a sorted DatetimeIndex and numeric values.
    """
    series = series.sort_index()
    if len(series) < 5:
        # too short to model; nothing flagged
        return pd.Series(False, index=series.index)

    if not _ADTK:
        return _mad_anomalies(series)

    try:  # pragma: no cover - exercised when adtk installed
        s = validate_series(series)
        persist = PersistAD(c=c, side="both", window=3)
        quant = QuantileAD(high=0.99, low=0.01)
        a1 = persist.fit_detect(s).fillna(False).astype(bool)
        a2 = quant.fit_detect(s).fillna(False).astype(bool)
        return (a1 | a2)
    except Exception as exc:  # pragma: no cover
        log.warning("ADTK detection failed, falling back to MAD: %s", exc)
        return _mad_anomalies(series)


def aggregate_metric(
    df: pd.DataFrame, value_col: str, time_col: str, rule: str
) -> pd.Series:
    """Resample raw events into a regular time series for a single entity."""
    s = df.set_index(pd.to_datetime(df[time_col]))[value_col]
    if value_col == "_count":
        return s.resample(rule).count()
    return s.resample(rule).sum()


def score_metric(
    df: pd.DataFrame, metric: str, time_col: str = "@timestamp"
) -> pd.DataFrame:
    """Run anomaly detection for a named metric over a window of events.

    Returns a DataFrame with columns: [timestamp, value, is_anomaly].
    """
    if metric not in METRICS:
        raise ValueError(f"unknown metric '{metric}'")
    rule = METRICS[metric]["rule"]
    df = df.copy()
    df["_count"] = 1
    value_col = "value" if "value" in df.columns else "_count"
    series = aggregate_metric(df, value_col, time_col, rule)
    flags = detect_series(series.astype(float))
    out = pd.DataFrame(
        {
            "timestamp": series.index,
            "value": series.values,
            "is_anomaly": flags.reindex(series.index).fillna(False).values,
        }
    )
    return out


def anomaly_score_from_flags(flags: pd.Series) -> float:
    """Collapse a window of boolean flags into a single [0,1] score."""
    if len(flags) == 0:
        return 0.0
    recent = flags.tail(min(len(flags), 12))
    return float(np.clip(recent.mean() * 1.5 + (0.4 if bool(flags.iloc[-1]) else 0.0), 0, 1))
