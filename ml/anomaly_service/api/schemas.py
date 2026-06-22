"""Pydantic request/response models for the anomaly API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    """A single security event to score. Free-form to accept Zeek/Suricata/
    Wazuh/Sysmon schemas; feature extraction handles the differences."""

    event: dict[str, Any] = Field(..., description="Normalized security event")
    sink: bool = Field(
        default=False, description="If true, also index the result to Elasticsearch"
    )


class ScoreResponse(BaseModel):
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    is_anomaly: bool
    threshold: float
    reason: str
    top_features: list[str]
    per_model: dict[str, float]
    bootstrapped_model: bool


class BatchScoreRequest(BaseModel):
    events: list[dict[str, Any]]
    sink: bool = False


class RetrainRequest(BaseModel):
    """Feature matrix as list-of-rows, or raw events to featurize."""

    events: list[dict[str, Any]] | None = None
    feature_matrix: list[list[float]] | None = None


class HealthResponse(BaseModel):
    status: str
    fitted: bool
    bootstrapped: bool
    detectors: list[str]
    trained_samples: int
    threshold: float
