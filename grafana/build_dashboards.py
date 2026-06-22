#!/usr/bin/env python3
"""Generate valid Grafana-11 Elasticsearch dashboards for sybsec and upload them.
Every target has metrics + a non-empty bucketAggs (Grafana 11's ES backend
rejects empty aggregations). Datasource uid is the pinned 'sybsec-es'."""
import json
import os
import urllib.request

GRAFANA = "http://localhost:3000"
AUTH = ("admin", "changeme_grafana")
DS = {"type": "elasticsearch", "uid": "sybsec-es"}
import os
OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboards")


def tgt(refid, query, metrics, buckets):
    return {
        "refId": refid, "datasource": DS, "query": query, "alias": "",
        "metrics": metrics, "bucketAggs": buckets, "timeField": "@timestamp",
    }


def dh(_id="2", interval="5m"):
    return {"id": _id, "type": "date_histogram", "field": "@timestamp",
            "settings": {"interval": interval, "min_doc_count": "0"}}


def terms(field, _id="3", size="10"):
    return {"id": _id, "type": "terms", "field": field,
            "settings": {"size": size, "order": "desc", "orderBy": "_count", "min_doc_count": "1"}}


COUNT = [{"id": "1", "type": "count"}]


def stat(pid, title, query, gp, unit="short", thresholds=None):
    fc = {"defaults": {"unit": unit, "color": {"mode": "thresholds"}}}
    if thresholds:
        fc["defaults"]["thresholds"] = {"mode": "absolute", "steps": thresholds}
    return {"id": pid, "type": "stat", "title": title, "datasource": DS, "gridPos": gp,
            "fieldConfig": fc,
            "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                        "colorMode": "value", "graphMode": "area"},
            "targets": [tgt("A", query, COUNT, [dh()])]}


def timeseries(pid, title, query, buckets, metrics, gp):
    return {"id": pid, "type": "timeseries", "title": title, "datasource": DS, "gridPos": gp,
            "fieldConfig": {"defaults": {"custom": {"fillOpacity": 10, "showPoints": "auto"}}},
            "targets": [tgt("A", query, metrics, buckets)]}


def table(pid, title, query, field, gp):
    return {"id": pid, "type": "table", "title": title, "datasource": DS, "gridPos": gp,
            "targets": [tgt("A", query, COUNT, [terms(field, "3", "10")])]}


def dashboard(uid, title, tags, panels, refresh="30s", time_from="now-24h"):
    return {"uid": uid, "title": title, "tags": tags, "timezone": "browser",
            "schemaVersion": 39, "version": 1, "refresh": refresh,
            "time": {"from": time_from, "to": "now"}, "templating": {"list": []},
            "annotations": {"list": []}, "panels": panels}


def H(x, y, w, h):
    return {"h": h, "w": w, "x": x, "y": y}


dashboards = {
    "soc_overview.json": dashboard(
        "sybsec-soc-overview", "sybsec — SOC Overview", ["sybsec", "soc"], [
            stat(1, "Total alerts (24h)", "event.kind:alert", H(0, 0, 6, 4)),
            stat(2, "ML anomalies (24h)", "event.module:\"ml-anomaly\" AND is_anomaly:true", H(6, 0, 6, 4),
                 thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}]),
            timeseries(3, "Alert rate by module", "event.kind:alert",
                       [terms("event.module", "3", "5"), dh("2")], COUNT, H(12, 0, 12, 8)),
            table(4, "Top source IPs", "event.kind:alert", "source.ip", H(0, 4, 12, 8)),
            timeseries(5, "Alerts by rule id", "event.kind:alert",
                       [terms("rule.id", "3", "10"), dh("2")], COUNT, H(12, 8, 12, 8)),
        ]),
    "anomaly_scores.json": dashboard(
        "sybsec-anomaly-scores", "sybsec — ML Anomaly Scores", ["sybsec", "ml"], [
            timeseries(1, "Mean anomaly score", "event.module:\"ml-anomaly\"",
                       [dh("2","1h")], [{"id": "1", "type": "avg", "field": "anomaly_score"}], H(0, 0, 24, 9)),
            timeseries(2, "Anomaly count over time", "is_anomaly:true",
                       [dh("2","1h")], COUNT, H(0, 9, 24, 9)),
        ], refresh="1m", time_from="now-7d"),
    "network_traffic.json": dashboard(
        "sybsec-network-traffic", "sybsec — Network Traffic", ["sybsec", "network"], [
            timeseries(1, "Suricata alerts over time", "event.module:suricata",
                       [dh("2")], COUNT, H(0, 0, 24, 8)),
            table(2, "Suricata alerts by signature", "event.module:suricata", "rule.name", H(0, 8, 12, 8)),
            table(3, "Top destination ports", "event.kind:alert", "destination.port", H(12, 8, 12, 8)),
        ], refresh="30s", time_from="now-24h"),
    "mttd_mttr.json": dashboard(
        "sybsec-mttd-mttr", "sybsec — SLA: MTTD / MTTR", ["sybsec", "sla"], [
            stat(1, "Alerts (count)", "event.kind:alert", H(0, 0, 8, 5)),
            stat(2, "Cases-worthy (level>=10)", "event.severity:>=10", H(8, 0, 8, 5)),
            timeseries(3, "Detection volume trend", "event.kind:alert", [dh("2","6h")], COUNT, H(0, 5, 24, 9)),
        ], refresh="5m", time_from="now-30d"),
}


def upload(name, dash):
    body = json.dumps({"dashboard": {**dash, "id": None}, "overwrite": True, "folderUid": ""}).encode()
    req = urllib.request.Request(f"{GRAFANA}/api/dashboards/db", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    import base64
    tok = base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
    req.add_header("Authorization", f"Basic {tok}")
    with urllib.request.urlopen(req, timeout=15) as r:
        res = json.load(r)
    return res.get("status"), res.get("uid")


for name, dash in dashboards.items():
    with open(os.path.join(OUTDIR, name), "w") as fh:
        json.dump(dash, fh, indent=2)
    try:
        status, uid = upload(name, dash)
        print(f"  {name}: file written + uploaded ({status})")
    except Exception as exc:
        print(f"  {name}: file written, upload FAILED: {exc}")
