"""Centralized configuration for the anomaly detection service.

All values are environment-driven (12-factor). Nothing security-relevant is
hardcoded; secrets come from the environment / .env file at deploy time.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # Service
    log_level: str = os.getenv("ML_LOG_LEVEL", "INFO")
    host: str = os.getenv("ML_HOST", "0.0.0.0")
    port: int = int(os.getenv("ML_PORT", "8088"))

    # Anomaly scoring
    threshold: float = float(os.getenv("ML_ANOMALY_THRESHOLD", "0.85"))
    # Weighted ensemble (must sum to ~1.0; normalized at runtime regardless).
    ensemble_weights: dict[str, float] = field(
        default_factory=lambda: {
            "iforest": float(os.getenv("ML_W_IFOREST", "0.35")),
            "autoencoder": float(os.getenv("ML_W_AUTOENCODER", "0.30")),
            "hbos": float(os.getenv("ML_W_HBOS", "0.15")),
            "lof": float(os.getenv("ML_W_LOF", "0.20")),
        }
    )

    # Elasticsearch (anomaly sink)
    es_hosts: list[str] = field(
        default_factory=lambda: _csv("ML_ES_HOSTS", "http://elasticsearch:9200")
    )
    es_index: str = os.getenv("ML_ES_INDEX", "security-anomalies")
    es_user: str = os.getenv("ML_ES_USER", "elastic")
    es_password: str = os.getenv("ELASTIC_PASSWORD", "")
    es_verify_certs: bool = os.getenv("ML_ES_VERIFY_CERTS", "false").lower() == "true"

    # Kafka (event source)
    kafka_bootstrap: str = os.getenv("KAFKA_BROKER", "kafka:9092")
    kafka_topics: list[str] = field(
        default_factory=lambda: _csv(
            "ML_KAFKA_TOPICS",
            "zeek-logs,suricata-alerts,wazuh-events,sysmon-events",
        )
    )
    kafka_group: str = os.getenv("ML_KAFKA_GROUP", "ml-anomaly")

    # Model persistence
    model_dir: str = os.getenv("ML_MODEL_DIR", "/app/models/artifacts")
    # Rolling baseline window (days) used to retrain.
    baseline_days: int = int(os.getenv("ML_BASELINE_DAYS", "30"))


settings = Settings()
