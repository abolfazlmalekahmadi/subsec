"""Elasticsearch sink for anomaly results.

Pushes scored anomalies to the `security-anomalies` index. Lazily constructs
the client so the service can run (and be tested) without a live ES.
"""
from __future__ import annotations

import logging
from typing import Any

from config import settings

log = logging.getLogger("ml.sink")

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        from elasticsearch import Elasticsearch

        _client = Elasticsearch(
            settings.es_hosts,
            basic_auth=(settings.es_user, settings.es_password)
            if settings.es_password
            else None,
            verify_certs=settings.es_verify_certs,
            request_timeout=5,
        )
        return _client
    except Exception as exc:  # pragma: no cover - ES optional at runtime
        log.warning("Elasticsearch client unavailable: %s", exc)
        return None


def index_anomaly(doc: dict[str, Any]) -> bool:
    """Index one anomaly document. Returns True on success, False otherwise."""
    client = _get_client()
    if client is None:
        return False
    try:  # pragma: no cover - requires live ES
        client.index(index=settings.es_index, document=doc)
        return True
    except Exception as exc:  # pragma: no cover
        log.warning("failed to index anomaly: %s", exc)
        return False
