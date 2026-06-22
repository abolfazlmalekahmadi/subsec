"""Tests for feature extraction stability and robustness."""
from models.features import (
    FEATURE_DIM,
    FEATURE_NAMES,
    explain,
    extract_features,
)


def test_feature_dim_matches_names():
    assert len(FEATURE_NAMES) == FEATURE_DIM


def test_extract_returns_fixed_length(normal_event):
    vec = extract_features(normal_event)
    assert len(vec) == FEATURE_DIM
    assert all(isinstance(x, float) for x in vec)


def test_empty_event_is_safe():
    vec = extract_features({})
    assert len(vec) == FEATURE_DIM
    assert all(x == x for x in vec)  # no NaN


def test_missing_fields_default_to_zero_region():
    vec = extract_features({"destination.port": 443})
    assert len(vec) == FEATURE_DIM


def test_failed_login_flag_detected(malicious_event):
    feats = explain(malicious_event, extract_features(malicious_event))
    assert feats["failed_login_flag"] == 1.0


def test_schema_variants_agree_on_length():
    zeek = {"id.orig_h": "1.2.3.4", "id.resp_p": 80, "orig_bytes": 100, "proto": "tcp"}
    suricata = {"src_ip": "1.2.3.4", "dest_port": 80, "app_proto": "http", "alert.severity": 2}
    sysmon = {"winlog.event_id": 1, "user.name": "bob", "host.name": "win01"}
    lengths = {len(extract_features(e)) for e in (zeek, suricata, sysmon)}
    assert lengths == {FEATURE_DIM}


def test_hashing_is_deterministic():
    e = {"source.ip": "8.8.8.8", "user.name": "carol"}
    assert extract_features(e) == extract_features(e)


def test_process_spawn_flag():
    feats = explain({}, extract_features({"winlog.event_id": "1"}))
    assert feats["process_spawn"] == 1.0
