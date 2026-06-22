"""PyOD ensemble anomaly detector.

Combines four complementary detectors into a single weighted score in [0, 1]:

  * IsolationForest  — general-purpose outlier detection on feature vectors
  * AutoEncoder      — deep reconstruction-error anomalies (complex patterns)
  * HBOS             — fast histogram-based detection for high-volume streams
  * LOF              — local outlier factor for density-based anomalies

Each detector's raw scores are converted to calibrated probabilities and then
combined with a normalized weighted average. Models persist to disk so the
service can reload a trained baseline on restart and retrain weekly.

The implementation degrades gracefully: if PyOD (and its heavier deps such as
TensorFlow/torch for the AutoEncoder) are unavailable, the ensemble falls back
to the detectors that *are* importable, and finally to a z-score baseline, so
the API and tests remain runnable in a minimal environment.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import joblib
import numpy as np

from .features import FEATURE_DIM

log = logging.getLogger("ml.ensemble")

# Try to import PyOD detectors individually; missing ones are simply skipped.
_DETECTORS: dict[str, type] = {}
try:  # pragma: no cover - import wiring
    from pyod.models.iforest import IForest

    _DETECTORS["iforest"] = IForest
except Exception as exc:  # pragma: no cover
    log.warning("IForest unavailable: %s", exc)
try:  # pragma: no cover
    from pyod.models.hbos import HBOS

    _DETECTORS["hbos"] = HBOS
except Exception as exc:  # pragma: no cover
    log.warning("HBOS unavailable: %s", exc)
try:  # pragma: no cover
    from pyod.models.lof import LOF

    _DETECTORS["lof"] = LOF
except Exception as exc:  # pragma: no cover
    log.warning("LOF unavailable: %s", exc)
try:  # pragma: no cover
    from pyod.models.auto_encoder import AutoEncoder

    _DETECTORS["autoencoder"] = AutoEncoder
except Exception as exc:  # pragma: no cover
    log.warning("AutoEncoder unavailable: %s", exc)


@dataclass
class ScoreResult:
    score: float                       # combined anomaly score in [0, 1]
    is_anomaly: bool
    per_model: dict[str, float]        # calibrated per-detector scores
    top_features: list[str]            # features deviating most from baseline
    threshold: float = 0.85            # decision threshold used


class AnomalyEnsemble:
    """Weighted ensemble of PyOD detectors with persistence."""

    def __init__(self, weights: dict[str, float], threshold: float = 0.85):
        self.threshold = threshold
        self.weights = self._normalize_weights(weights)
        self.models: dict[str, object] = {}
        self.feature_mean = np.zeros(FEATURE_DIM)
        self.feature_std = np.ones(FEATURE_DIM)
        self._fitted = False

    @staticmethod
    def _normalize_weights(weights: dict[str, float]) -> dict[str, float]:
        active = {k: v for k, v in weights.items() if k in _DETECTORS}
        total = sum(active.values())
        if total <= 0:
            # equal weight across whatever detectors are available
            n = max(len(_DETECTORS), 1)
            return {k: 1.0 / n for k in _DETECTORS}
        return {k: v / total for k, v in active.items()}

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def fit(self, X: np.ndarray) -> AnomalyEnsemble:
        X = np.asarray(X, dtype=float)
        if X.ndim != 2 or X.shape[1] != FEATURE_DIM:
            raise ValueError(f"expected (n, {FEATURE_DIM}) feature matrix, got {X.shape}")
        self.feature_mean = X.mean(axis=0)
        self.feature_std = X.std(axis=0) + 1e-9

        self.models = {}
        for name, cls in _DETECTORS.items():
            try:
                model = self._build(name, cls, n=len(X))
                model.fit(X)
                self.models[name] = model
            except Exception as exc:  # pragma: no cover - per-detector resilience
                log.warning("detector %s failed to fit, skipping: %s", name, exc)
        self._fitted = True
        log.info("ensemble fitted with detectors: %s", list(self.models))
        return self

    @staticmethod
    def _build(name: str, cls: type, n: int):
        if name == "iforest":
            return cls(contamination=0.02, n_estimators=200, random_state=42)
        if name == "lof":
            return cls(contamination=0.02, n_neighbors=min(20, max(2, n - 1)))
        if name == "hbos":
            return cls(contamination=0.02, n_bins=10)
        if name == "autoencoder":  # pragma: no cover - heavy dep
            return cls(contamination=0.02, epoch_num=20, verbose=0)
        return cls()

    def _calibrated(self, name: str, X: np.ndarray) -> np.ndarray:
        """Per-detector anomaly probability in [0, 1]."""
        model = self.models[name]
        if hasattr(model, "predict_proba"):
            try:
                return model.predict_proba(X)[:, 1]
            except Exception:  # pragma: no cover
                pass
        raw = model.decision_function(X)
        lo, hi = float(np.min(raw)), float(np.max(raw))
        if hi - lo < 1e-12:
            return np.full(len(X), 0.5)
        return (raw - lo) / (hi - lo)

    def _zscore_fallback(self, X: np.ndarray) -> np.ndarray:
        z = np.abs((X - self.feature_mean) / self.feature_std)
        # squash max-z per row into [0,1)
        return 1.0 - np.exp(-z.max(axis=1) / 3.0)

    def score(self, X: np.ndarray) -> list[ScoreResult]:
        X = np.atleast_2d(np.asarray(X, dtype=float))
        if not self._fitted:
            raise RuntimeError("ensemble not fitted; call fit() or load() first")

        per_model_all: dict[str, np.ndarray] = {}
        for name in self.models:
            try:
                per_model_all[name] = self._calibrated(name, X)
            except Exception as exc:  # pragma: no cover
                log.warning("scoring with %s failed: %s", name, exc)

        if per_model_all:
            combined = np.zeros(len(X))
            wsum = 0.0
            for name, scores in per_model_all.items():
                w = self.weights.get(name, 0.0)
                combined += w * scores
                wsum += w
            combined = combined / wsum if wsum > 0 else combined
        else:  # pragma: no cover - extreme fallback
            combined = self._zscore_fallback(X)

        results: list[ScoreResult] = []
        z = np.abs((X - self.feature_mean) / self.feature_std)
        from .features import FEATURE_NAMES

        for i in range(len(X)):
            top_idx = np.argsort(z[i])[::-1][:3]
            results.append(
                ScoreResult(
                    score=float(np.clip(combined[i], 0.0, 1.0)),
                    is_anomaly=bool(combined[i] >= self.threshold),
                    per_model={k: float(v[i]) for k, v in per_model_all.items()},
                    top_features=[FEATURE_NAMES[j] for j in top_idx],
                    threshold=self.threshold,
                )
            )
        return results

    def score_one(self, vector: list[float]) -> ScoreResult:
        return self.score(np.array([vector]))[0]

    # --- persistence ---------------------------------------------------------
    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(
            {
                "weights": self.weights,
                "threshold": self.threshold,
                "models": self.models,
                "feature_mean": self.feature_mean,
                "feature_std": self.feature_std,
                "fitted": self._fitted,
            },
            path,
        )
        log.info("ensemble saved to %s", path)

    @classmethod
    def load(cls, path: str) -> AnomalyEnsemble:
        blob = joblib.load(path)
        inst = cls(weights=blob["weights"], threshold=blob["threshold"])
        inst.models = blob["models"]
        inst.feature_mean = blob["feature_mean"]
        inst.feature_std = blob["feature_std"]
        inst._fitted = blob["fitted"]
        return inst
