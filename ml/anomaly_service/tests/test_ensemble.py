"""Tests for the PyOD ensemble: fit, score range, anomaly separation, persist."""
import numpy as np
import pytest

from models.ensemble import AnomalyEnsemble
from models.features import FEATURE_DIM, extract_features

WEIGHTS = {"iforest": 0.35, "autoencoder": 0.30, "hbos": 0.15, "lof": 0.20}


@pytest.fixture
def ensemble():
    rng = np.random.default_rng(0)
    X = rng.normal(0.3, 0.1, size=(400, FEATURE_DIM)).clip(0, 1)
    return AnomalyEnsemble(weights=WEIGHTS, threshold=0.85).fit(X)


def test_fit_marks_fitted(ensemble):
    assert ensemble.is_fitted
    assert len(ensemble.models) >= 1  # at least one detector available


def test_weights_normalized(ensemble):
    assert abs(sum(ensemble.weights.values()) - 1.0) < 1e-6


def test_score_in_unit_interval(ensemble):
    rng = np.random.default_rng(1)
    X = rng.normal(0.3, 0.1, size=(20, FEATURE_DIM)).clip(0, 1)
    for r in ensemble.score(X):
        assert 0.0 <= r.score <= 1.0


def test_obvious_outlier_scores_higher_than_normal(ensemble):
    normal = np.full((1, FEATURE_DIM), 0.3)
    outlier = np.full((1, FEATURE_DIM), 0.99)
    s_normal = ensemble.score(normal)[0].score
    s_outlier = ensemble.score(outlier)[0].score
    assert s_outlier > s_normal


def test_score_one_returns_top_features(ensemble):
    r = ensemble.score_one([0.99] * FEATURE_DIM)
    assert len(r.top_features) == 3
    assert isinstance(r.per_model, dict)


def test_unfitted_raises():
    ens = AnomalyEnsemble(weights=WEIGHTS)
    with pytest.raises(RuntimeError):
        ens.score(np.zeros((1, FEATURE_DIM)))


def test_bad_shape_raises():
    ens = AnomalyEnsemble(weights=WEIGHTS)
    with pytest.raises(ValueError):
        ens.fit(np.zeros((10, 3)))


def test_persistence_roundtrip(ensemble, tmp_path):
    path = str(tmp_path / "ens.joblib")
    ensemble.save(path)
    loaded = AnomalyEnsemble.load(path)
    assert loaded.is_fitted
    v = [0.5] * FEATURE_DIM
    assert abs(loaded.score_one(v).score - ensemble.score_one(v).score) < 1e-9


def test_real_event_through_pipeline(ensemble, malicious_event, normal_event):
    s_mal = ensemble.score_one(extract_features(malicious_event)).score
    s_norm = ensemble.score_one(extract_features(normal_event)).score
    assert s_mal >= s_norm
