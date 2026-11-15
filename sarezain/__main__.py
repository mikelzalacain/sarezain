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
        result = asyncio.run(scanner.run_scan(args.network, progress, profile=args.profile, check_cves=not args.no_cve))
    except safety.UnsafeTargetError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0

    s = result["summary"]
    print(f"\n\nRed {result['network']} · {s['hosts']} dispositivos · {s['open_ports']} puertos abiertos "
          f"({result['ports_scanned']} analizados por equipo) · {result['duration']} s · "
          f"riesgo {s['risk']}/100 ({LEVEL_LABEL[s['level']]})\n")
    for title, block in (("RED", result["network_audit"]), ("ESTE EQUIPO", result.get("local_audit") or {})):
        if block.get("findings"):
            print(f"  [{title}]")
            for fnd in block["findings"]:
                print(f"      - [{LEVEL_LABEL[fnd['severity']]}] {fnd['title']} → {fnd['fix']}")
    print("  [DISPOSITIVOS]")
    for h in sorted(result["hosts"], key=lambda x: -x["risk"]):
        name = h["model"] or h["hostname"] or h["vendor"] or "?"
        ports_txt = ",".join(str(x["port"]) for x in h["services"]) or "-"
        print(f"  {h['ip']:<15} {h['type']:<11} {LEVEL_LABEL[h['level']]:<8} {name[:34]:<34} {h.get('os') or '':<22} puertos: {ports_txt}")
        for fnd in h["findings"]:
            print(f"      - [{LEVEL_LABEL[fnd['severity']]}] {fnd['title']} → {fnd['fix']}")
    return 0


def _port_in_use(port: int) -> bool:
    import socket
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def cmd_serve(args) -> int:
    import threading
    import webbrowser

    import uvicorn

    from .server import app  # objeto directo: funciona también empaquetado (.exe)

    url = f"http://127.0.0.1:{args.port}"
    if _port_in_use(args.port):
        # Probablemente Sarezain ya está abierto: reutilizarlo en vez de fallar.
        print(f"Sarezain ya está en marcha en {url}; abriendo el panel…")
        if not args.no_browser:
            webbrowser.open(url)
        return 0

    print(f"Sarezain {__version__}")
    print(f"Panel abierto en {url}")
    print("Deja esta ventana abierta mientras lo uses. Para salir, ciérrala o pulsa Ctrl+C.\n")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="sarezain", description="Escáner visual de vulnerabilidades para tu red local.")
    parser.add_argument("--version", action="version", version=f"sarezain {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="escanear desde la terminal")
    p_scan.add_argument("network", nargs="?", help="red a escanear (CIDR). Por defecto, la red local")
    p_scan.add_argument("--json", action="store_true", help="salida en JSON")
    p_scan.add_argument("--profile", choices=["rapido", "completo"], default="completo",
                        help="rapido: 60 puertos · completo: ~1.150 puertos (por defecto)")
    p_scan.add_argument("--no-cve", action="store_true", help="no consultar la base de datos de CVE (sin Internet)")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="abrir el panel web (por defecto)")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--no-browser", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    if not args.cmd:
        args = parser.parse_args(["serve", *sys.argv[1:]])
    return args.func(args)


def run() -> int:
    """Entrada del .exe: si algo falla, deja la ventana abierta para poder leer el error."""
    # Al redirigir la salida (> informe.txt, tuberías) Windows usa cp1252, que no tiene → · ✓…
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        return main()
    except KeyboardInterrupt:
        return 0
    except Exception:
        import traceback
        traceback.print_exc()
        if getattr(sys, "frozen", False):
            input("\nSe ha producido un error. Pulsa Enter para cerrar…")
        return 1


if __name__ == "__main__":
    sys.exit(run())
