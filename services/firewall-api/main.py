"""sybsec firewall-api — a minimal blocklist service.

A stand-in for a real firewall's block API (pfSense alias / iptables ipset) that
the SOAR layer (Shuffle) can call to block a source IP, and that a demo can
verify. The blocklist persists to a file so it survives restarts.

Endpoints:
    GET  /health           -> {"status":"ok","blocked":N}
    GET  /blocklist        -> {"blocked":[{ip,reason,at}, ...]}
    POST /block            -> {"blocked":true,"ip":...}    body: {ip, reason?}
    POST /unblock          -> {"unblocked":true,"ip":...}  body: {ip}
"""
from __future__ import annotations

import json
import os
import time

from fastapi import FastAPI
from pydantic import BaseModel

BLOCKLIST = os.getenv("FW_BLOCKLIST", "/data/blocklist.json")
app = FastAPI(title="sybsec firewall-api", version="1.0.0")


def _load() -> dict:
    try:
        with open(BLOCKLIST) as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {}


def _save(data: dict) -> None:
    os.makedirs(os.path.dirname(BLOCKLIST), exist_ok=True)
    with open(BLOCKLIST, "w") as fh:
        json.dump(data, fh)


class BlockReq(BaseModel):
    ip: str
    reason: str = "blocked by sybsec SOAR"


class UnblockReq(BaseModel):
    ip: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "blocked": len(_load())}


@app.get("/blocklist")
def blocklist() -> dict:
    data = _load()
    return {"count": len(data), "blocked": list(data.values())}


@app.post("/block")
def block(req: BlockReq) -> dict:
    data = _load()
    existed = req.ip in data
    data[req.ip] = {"ip": req.ip, "reason": req.reason, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}
    _save(data)
    return {"blocked": True, "ip": req.ip, "already_blocked": existed, "total": len(data)}


@app.post("/unblock")
def unblock(req: UnblockReq) -> dict:
    data = _load()
    removed = data.pop(req.ip, None) is not None
    _save(data)
    return {"unblocked": removed, "ip": req.ip, "total": len(data)}
