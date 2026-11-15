"""Punto de entrada.

    python -m sarezain                 abre el panel web en http://127.0.0.1:8765
    python -m sarezain scan            escanea desde la terminal y muestra un resumen
    python -m sarezain scan --json     igual, pero vuelca el resultado en JSON
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__

LEVEL_LABEL = {"critica": "CRÍTICO", "alta": "ALTO", "media": "MEDIO", "baja": "BAJO", "ok": "OK", "info": "INFO"}


def cmd_scan(args) -> int:
    from . import safety, scanner

    def progress(_key, label, value):
        if not args.json:
            print(f"\r[{value * 100:5.1f}%] {label:<26}", end="", flush=True)

    try:
        result = asyncio.run(scanner.run_scan(args.network, progress))
    except safety.UnsafeTargetError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0

    s = result["summary"]
    print(f"\n\nRed {result['network']} · {s['hosts']} dispositivos · {s['open_ports']} puertos abiertos · "
          f"{result['duration']} s · riesgo {s['risk']}/100 ({LEVEL_LABEL[s['level']]})\n")
    for h in sorted(result["hosts"], key=lambda x: -x["risk"]):
        name = h["hostname"] or h["vendor"] or "?"
        ports_txt = ",".join(str(x["port"]) for x in h["services"]) or "-"
        print(f"  {h['ip']:<15} {h['type']:<11} {LEVEL_LABEL[h['level']]:<8} {name[:34]:<34} puertos: {ports_txt}")
        for fnd in h["findings"]:
            print(f"      - [{LEVEL_LABEL[fnd['severity']]}] {fnd['title']}")
    return 0


def cmd_serve(args) -> int:
    import threading
    import webbrowser

    import uvicorn

    url = f"http://127.0.0.1:{args.port}"
    print(f"Sarezain {__version__} · panel en {url}  (Ctrl+C para salir)")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run("sarezain.server:app", host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="sarezain", description="Escáner visual de vulnerabilidades para tu red local.")
    parser.add_argument("--version", action="version", version=f"sarezain {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="escanear desde la terminal")
    p_scan.add_argument("network", nargs="?", help="red a escanear (CIDR). Por defecto, la red local")
    p_scan.add_argument("--json", action="store_true", help="salida en JSON")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="abrir el panel web (por defecto)")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--no-browser", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    if not args.cmd:
        args = parser.parse_args(["serve", *sys.argv[1:]])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
