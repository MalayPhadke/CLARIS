"""Persistence helpers to save/load minimal connection metadata."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger("vigilink.backend.persistence")

CONN_STORE = Path(__file__).parent / ".vigilink_conns.json"


def save_connections_to_disk(connections: Dict[str, Dict[str, Any]]) -> None:
    data = {}
    for uid, meta in connections.items():
        rec = {}
        if "container_id" in meta:
            rec["container_id"] = meta.get("container_id")
        if "container_started_at" in meta:
            rec["container_started_at"] = meta.get("container_started_at")
        if "ssh_hop_config" in meta:
            rec["ssh_hop_config"] = meta.get("ssh_hop_config")
        if rec:
            data[uid] = rec
    try:
        CONN_STORE.write_text(json.dumps(data))
    except Exception:
        logger.exception("failed to save connections to disk")


def load_connections_from_disk(connections: Dict[str, Dict[str, Any]]) -> None:
    if not CONN_STORE.exists():
        return
    try:
        raw = CONN_STORE.read_text()
        obj = json.loads(raw)
    except Exception:
        logger.exception("failed to read connections file")
        return
    for uid, rec in obj.items():
        connections[uid] = rec
