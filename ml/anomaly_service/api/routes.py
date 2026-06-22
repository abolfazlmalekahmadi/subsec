"""REST routes for the anomaly detection service."""
from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException

from api.schemas import (
    BatchScoreRequest,
    HealthResponse,
    RetrainRequest,
    ScoreRequest,
    ScoreResponse,
)
from api.sink import index_anomaly
from config import settings
from models import timeseries
from models.features import explain, extract_features
from models.store import store

log = logging.getLogger("ml.routes")
router = APIRouter()


def _build_reason(result, feats: dict[str, float]) -> str:
    if not result.is_anomaly:
        return "within learned baseline"
    drivers = ", ".join(result.top_features)
    contributors = sorted(result.per_model.items(), key=lambda kv: kv[1], reverse=True)
    top_model = contributors[0][0] if contributors else "ensemble"
    return (
        f"anomaly score {result.score:.3f} >= {result.threshold:.2f}; "
        f"primary detector={top_model}; deviating features: {drivers}"
    )


def _anomaly_doc(event: dict, result, reason: str) -> dict:
    return {
        "@timestamp": event.get("@timestamp"),
        "event.kind": "alert",
        "event.module": "ml-anomaly",
        "anomaly_score": result.score,
        "is_anomaly": result.is_anomaly,
        "threshold": result.threshold,
        "reason": reason,
        "top_features": result.top_features,
        "per_model": result.per_model,
        "source": {"ip": event.get("source.ip") or event.get("src_ip")},
        "user": {"name": event.get("user.name") or event.get("user")},
        "host": {"name": event.get("host.name") or event.get("host")},
        "original_event_type": event.get("event_type") or event.get("event.module"),
    }


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    ens = store.require()
    return HealthResponse(
        status="ok",
        fitted=ens.is_fitted,
        bootstrapped=store.bootstrapped,
        detectors=list(ens.models),
        trained_samples=store.trained_samples,
        threshold=ens.threshold,
    )


@router.get("/ready")
def ready() -> dict:
    return {"ready": store.require().is_fitted}


@router.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    ens = store.require()
    vector = extract_features(req.event)
    result = ens.score_one(vector)
    feats = explain(req.event, vector)
    reason = _build_reason(result, feats)

    if req.sink and result.is_anomaly:
        index_anomaly(_anomaly_doc(req.event, result, reason))

    return ScoreResponse(
        anomaly_score=result.score,
        is_anomaly=result.is_anomaly,
        threshold=result.threshold,
        reason=reason,
        top_features=result.top_features,
        per_model=result.per_model,
        bootstrapped_model=store.bootstrapped,
    )


@router.post("/score/batch")
def score_batch(req: BatchScoreRequest) -> dict:
    ens = store.require()
    if not req.events:
        return {"results": [], "count": 0}
    matrix = np.array([extract_features(e) for e in req.events])
    results = ens.score(matrix)
    out = []
    for event, result in zip(req.events, results, strict=True):
        reason = _build_reason(result, {})
        if req.sink and result.is_anomaly:
            index_anomaly(_anomaly_doc(event, result, reason))
        out.append(
            {
                "anomaly_score": result.score,
                "is_anomaly": result.is_anomaly,
                "reason": reason,
                "top_features": result.top_features,
            }
        )
    return {"results": out, "count": len(out), "anomalies": sum(r["is_anomaly"] for r in out)}


@router.post("/score/timeseries")
def score_timeseries(payload: dict) -> dict:
    """Score a metric time series.

    Body: {"metric": "<name>", "events": [{"@timestamp": ..., "value": ...}, ...]}
    """
    metric = payload.get("metric")
    events = payload.get("events", [])
    if metric not in timeseries.METRICS:
        raise HTTPException(400, f"unknown metric; choose from {list(timeseries.METRICS)}")
    if not events:
        raise HTTPException(400, "no events provided")
    df = pd.DataFrame(events)
    result = timeseries.score_metric(df, metric)
    flags = result["is_anomaly"]
    return {
        "metric": metric,
        "points": len(result),
        "anomalous_points": int(flags.sum()),
        "window_score": timeseries.anomaly_score_from_flags(flags),
        "series": result.to_dict(orient="records"),
    }


@router.post("/retrain")
def retrain(req: RetrainRequest) -> dict:
    if req.feature_matrix:
        X = np.array(req.feature_matrix)
    elif req.events:
        X = np.array([extract_features(e) for e in req.events])
    else:
        raise HTTPException(400, "provide either feature_matrix or events")
    if len(X) < 50:
        raise HTTPException(400, "need >= 50 samples to retrain a stable baseline")
    info = store.retrain(X)
    return {"status": "retrained", **info, "threshold": settings.threshold}
