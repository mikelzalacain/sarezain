"""Construye la demo estática (sin backend) en demo-dist/, lista para Cloudflare Pages.

Uso:  python tools/make_demo.py   (si cambian las reglas)
      python tools/build_demo.py
"""

import hashlib
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "sarezain" / "web"
OUT = ROOT / "demo-dist"

HEADERS = """/*
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains

/*.js
  Cache-Control: public, max-age=31536000, immutable
/*.css
  Cache-Control: public, max-age=31536000, immutable
"""


def main() -> None:
    if not (WEB / "demo.json").exists():
        raise SystemExit("Falta demo.json: ejecuta antes tools/make_demo.py")
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(WEB, OUT)
    (OUT / "demo-config.js").write_text("window.SAREZAIN_DEMO = true;\n", encoding="utf-8")
    (OUT / "_headers").write_text(HEADERS, encoding="utf-8")

    html = (OUT / "index.html").read_text(encoding="utf-8")
    html = html.replace('<script src="app.js"></script>', '<script src="demo-config.js"></script>\n  <script src="app.js"></script>')
    # Versionado por contenido: los navegadores siempre descargan la versión nueva.
    for name in ("app.css", "app.js", "demo-config.js", "vendor/cytoscape.min.js"):
        digest = hashlib.sha256((OUT / name).read_bytes()).hexdigest()[:10]
        html = re.sub(rf'(["\']){re.escape(name)}(["\'])', rf"\g<1>{name}?v={digest}\g<2>", html)
    html = html.replace("<title>Sarezain · Auditoría de red</title>", "<title>Sarezain · Demo</title>")
    (OUT / "index.html").write_text(html, encoding="utf-8")
    print(f"Demo lista en {OUT}")
    for p in sorted(OUT.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(OUT)}  {p.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
