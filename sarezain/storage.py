"""Historial de escaneos en ~/.sarezain/scans (JSON)."""

from __future__ import annotations

import json
import re
from pathlib import Path

BASE = Path.home() / ".sarezain" / "scans"


def save(scan: dict) -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    (BASE / f"{scan['id']}.json").write_text(json.dumps(scan, ensure_ascii=False, indent=1), encoding="utf-8")


def list_scans() -> list[dict]:
    if not BASE.exists():
        return []
    items = []
    for p in sorted(BASE.glob("*.json"), reverse=True):
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items.append({"id": s["id"], "started": s["started"], "network": s["network"],
                      "hosts": len(s["hosts"]), "risk": s["summary"]["risk"]})
    return items


def load(scan_id: str) -> dict | None:
    if not re.fullmatch(r"[\w\-]+", scan_id):
        return None
    p = BASE / f"{scan_id}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def latest(network: str | None = None) -> dict | None:
    for item in list_scans():
        if network is None or item["network"] == network:
            return load(item["id"])
    return None
