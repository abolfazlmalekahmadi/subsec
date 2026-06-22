"""Model lifecycle: load-or-bootstrap the ensemble, retrain, persist.

On first start there is usually no trained artifact. Rather than fail closed,
the store bootstraps a baseline from a synthetic "normal" distribution so the
service is immediately scoring; this is replaced the first time a real 30-day
baseline is fed via `retrain()`. The bootstrap is clearly flagged in /health.
"""
from __future__ import annotations

import logging
import os

import numpy as np

from config import settings
from models.ensemble import AnomalyEnsemble

log = logging.getLogger("ml.store")

_ARTIFACT = "ensemble.joblib"


class ModelStore:
    def __init__(self) -> None:
        self.ensemble: AnomalyEnsemble | None = None
        self.bootstrapped = False
        self.trained_samples = 0

    @property
    def artifact_path(self) -> str:
        return os.path.join(settings.model_dir, _ARTIFACT)

    def load_or_bootstrap(self) -> AnomalyEnsemble:
        if os.path.exists(self.artifact_path):
            try:
                self.ensemble = AnomalyEnsemble.load(self.artifact_path)
                self.bootstrapped = False
                log.info("loaded ensemble artifact from %s", self.artifact_path)
                return self.ensemble
            except Exception as exc:  # pragma: no cover
                log.warning("failed to load artifact, bootstrapping: %s", exc)
        return self._bootstrap()

    def _bootstrap(self) -> AnomalyEnsemble:
        # Cold-start baseline: realistic benign events through the real feature
        # pipeline (see models/synthetic.py). Training on the true feature
        # manifold is what prevents a false-positive storm on real traffic.
        from .synthetic import benign_baseline

        X = benign_baseline(n=3000, seed=42)
        ens = AnomalyEnsemble(
            weights=settings.ensemble_weights, threshold=settings.threshold
        )
        ens.fit(X)
        self.ensemble = ens
        self.bootstrapped = True
        self.trained_samples = len(X)
        log.warning("ensemble bootstrapped on synthetic baseline (not production-trained)")
        return ens

    def retrain(self, X: np.ndarray) -> dict:
        """Retrain on a real feature matrix (rolling baseline) and persist."""
        X = np.asarray(X, dtype=float)
        ens = AnomalyEnsemble(
            weights=settings.ensemble_weights, threshold=settings.threshold
        )
        ens.fit(X)
        ens.save(self.artifact_path)
        self.ensemble = ens
        self.bootstrapped = False
        self.trained_samples = len(X)
        log.info("retrained on %d samples and persisted", len(X))
        return {"samples": len(X), "detectors": list(ens.models)}

    def require(self) -> AnomalyEnsemble:
        if self.ensemble is None:
            self.load_or_bootstrap()
        assert self.ensemble is not None
        return self.ensemble


store = ModelStore()
