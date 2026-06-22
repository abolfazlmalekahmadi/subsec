"""Shared config for end-to-end detection tests.

These run against a LIVE sybsec stack (./scripts/deploy.sh up). Tests that need
a component which isn't up are skipped, not failed, so the suite is meaningful
at any deployment completeness.
"""
import os

import pytest

ML_URL = os.getenv("ML_URL", "http://localhost:8088")
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme_elastic")


def _reachable(url: str, **kw) -> bool:
    import requests

    try:
        requests.get(url, timeout=2, **kw)
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def ml_url():
    if not _reachable(f"{ML_URL}/health"):
        pytest.skip("ML anomaly service not reachable; start the stack first")
    return ML_URL


@pytest.fixture(scope="session")
def es():
    auth = (ES_USER, ES_PASSWORD)
    if not _reachable(f"{ES_URL}/_cluster/health", auth=auth):
        pytest.skip("Elasticsearch not reachable; start the stack first")
    return {"url": ES_URL, "auth": auth}
