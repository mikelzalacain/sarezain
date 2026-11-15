"""Identificación del fabricante a partir de la MAC (registro OUI del IEEE)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

OUI_FILE = Path(__file__).parent / "data" / "oui.txt"


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with OUI_FILE.open(encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or "\t" not in line:
                    continue
                prefix, name = line.rstrip("\n").split("\t", 1)
                table[prefix] = name
    except OSError:
        pass
    return table


def is_randomized(mac: str) -> bool:
    """MAC administrada localmente (bit U/L): típica de móviles con 'MAC privada'."""
    try:
        first = int(mac.replace(":", "").replace("-", "")[:2], 16)
    except ValueError:
        return False
    return bool(first & 0x02)


def lookup(mac: str | None) -> str | None:
    if not mac:
        return None
    if is_randomized(mac):
        return "MAC privada (aleatoria)"
    return _table().get(mac.replace(":", "").replace("-", "").upper()[:6])
