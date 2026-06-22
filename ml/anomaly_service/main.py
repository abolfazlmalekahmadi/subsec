"""FastAPI entrypoint for the sybsec ML anomaly detection service.

Run locally:
    uvicorn main:app --host 0.0.0.0 --port 8088

Endpoints:
    GET  /health              service + model status
    GET  /ready               readiness probe
    POST /score               score a single event -> anomaly_score + reason
    POST /score/batch         score many events
    POST /score/timeseries    ADTK metric scoring (login freq, bytes, etc.)
    POST /retrain             retrain ensemble on a rolling baseline
"""
from __future__ import annotations

import logging

from fastapi import FastAPI

from api.routes import router
from config import settings
from models.store import store

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ml.main")

app = FastAPI(
    title="sybsec ML Anomaly Service",
    version="0.1.0",
    description="PyOD ensemble + ADTK time-series anomaly detection for the SOC.",
)
app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    store.load_or_bootstrap()
    log.info(
        "anomaly service ready (bootstrapped=%s, threshold=%.2f)",
        store.bootstrapped,
        settings.threshold,
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)
