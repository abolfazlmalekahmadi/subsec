"""Kafka consumer: stream events from sensor topics, score them, and push
anomalies to Elasticsearch.

Topics (see kafka/topics.sh): zeek-logs, suricata-alerts, wazuh-events,
sysmon-events. Runs as a standalone worker process alongside the API:

    python -m consumers.kafka_consumer

It reuses the same ModelStore and feature pipeline as the REST API, so scoring
is identical whether an event arrives via Kafka or HTTP.
"""
from __future__ import annotations

import json
import logging
import signal
import sys

from api.routes import _anomaly_doc, _build_reason
from api.sink import index_anomaly
from config import settings
from models.features import explain, extract_features
from models.store import store

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("ml.consumer")

_running = True


def _stop(*_a):  # pragma: no cover - signal handler
    global _running
    _running = False
    log.info("shutdown signal received, draining...")


def build_consumer():
    """Construct a confluent-kafka Consumer. Imported lazily so unit tests do
    not require a running broker."""
    from confluent_kafka import Consumer

    return Consumer(
        {
            "bootstrap.servers": settings.kafka_bootstrap,
            "group.id": settings.kafka_group,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        }
    )


def handle_message(raw: bytes) -> dict | None:
    """Score one raw Kafka message; return the anomaly doc if anomalous."""
    try:
        event = json.loads(raw)
    except (ValueError, TypeError) as exc:
        log.debug("skipping non-JSON message: %s", exc)
        return None

    ens = store.require()
    vector = extract_features(event)
    result = ens.score_one(vector)
    if not result.is_anomaly:
        return None
    reason = _build_reason(result, explain(event, vector))
    doc = _anomaly_doc(event, result, reason)
    index_anomaly(doc)
    log.info("ANOMALY score=%.3f reason=%s", result.score, reason)
    return doc


def run() -> None:  # pragma: no cover - requires live Kafka
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    store.load_or_bootstrap()

    consumer = build_consumer()
    consumer.subscribe(settings.kafka_topics)
    log.info("consuming topics: %s", settings.kafka_topics)
    try:
        while _running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                log.warning("kafka error: %s", msg.error())
                continue
            handle_message(msg.value())
    finally:
        consumer.close()
        log.info("consumer closed")


if __name__ == "__main__":  # pragma: no cover
    run()
    sys.exit(0)
