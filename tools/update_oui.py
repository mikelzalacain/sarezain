"""Descarga el registro oficial OUI del IEEE y genera sarezain/data/oui.txt.

Uso:  python tools/update_oui.py              (descarga oui.csv del IEEE)
      python tools/update_oui.py oui.csv      (usa un oui.csv ya descargado)
"""

import csv
import io
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parent.parent / "sarezain" / "data" / "oui.txt"

SUFFIXES = re.compile(
    r"[,.]?\s*\b(inc|incorporated|corp|corporation|co|ltd|limited|llc|gmbh|ag|sa|s\.a|"
    r"bv|b\.v|nv|oy|ab|as|srl|spa|s\.p\.a|kk|plc|pte|pty|technology|technologies|"
    r"electronics|communications|international|holdings|group|company)\b\.?",
    re.IGNORECASE,
)


def short_name(name: str) -> str:
    name = re.sub(r"\s+", " ", name).strip()
    prev = None
    while prev != name:
        prev = name
        name = SUFFIXES.sub("", name).strip(" ,.-")
    return name or prev


def main() -> None:
    if len(sys.argv) > 1:
        data = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "sarezain-oui-updater"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    rows = csv.DictReader(io.StringIO(data))
    entries = {}
    for row in rows:
        prefix = (row.get("Assignment") or "").strip().upper()
        name = (row.get("Organization Name") or "").strip()
        if len(prefix) == 6 and name:
            entries[prefix] = short_name(name)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# Fuente: IEEE Registration Authority (MA-L). Generado por tools/update_oui.py\n")
        for prefix in sorted(entries):
            f.write(f"{prefix}\t{entries[prefix]}\n")
    print(f"{len(entries)} fabricantes -> {OUT}")


if __name__ == "__main__":
    main()
