"""Vulnerabilidades conocidas (CVE) por producto y versión, desde la NVD del NIST.

Privacidad: a la NVD solo se envía el producto y la versión (p. ej. "openssh 8.9p1"),
nunca IPs ni datos de tu red. Los resultados se guardan 7 días en ~/.sarezain/cve_cache.json.
Con una clave gratuita de la NVD en SAREZAIN_NVD_KEY las consultas son más rápidas.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import truststore  # usa el almacén de certificados del sistema (antivirus/proxy corporativo)
    _CTX = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
except ImportError:  # pragma: no cover
    _CTX = ssl.create_default_context()

API = "https://services.nvd.nist.gov/rest/json"
CACHE = Path.home() / ".sarezain" / "cve_cache.json"
TTL = 7 * 24 * 3600
KEY = os.environ.get("SAREZAIN_NVD_KEY")
_last_calls: list[float] = []

# Producto detectado -> (vendor, product) en el diccionario CPE
CPE_MAP = {
    "openssh": ("openbsd", "openssh"), "dropbear ssh": ("dropbear_ssh_project", "dropbear_ssh"),
    "apache": ("apache", "http_server"), "nginx": [("f5", "nginx"), ("nginx", "nginx")], "lighttpd": ("lighttpd", "lighttpd"),
    "microsoft-iis": ("microsoft", "internet_information_services"), "vsftpd": ("beasts", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"), "filezilla server": ("filezilla-project", "filezilla_server"),
    "mysql": ("oracle", "mysql"), "mariadb": ("mariadb", "mariadb"), "exim": ("exim", "exim"),
    "mini_httpd": ("acme", "mini_httpd"), "boa": ("boa", "boa"), "jetty": ("eclipse", "jetty"),
    "elasticsearch": ("elastic", "elasticsearch"), "openresty": ("openresty", "openresty"),
    "caddy": ("caddyserver", "caddy"), "tomcat": ("apache", "tomcat"), "goahead": ("embedthis", "goahead"),
}


def _cache() -> dict:
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(data: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(data), encoding="utf-8")


def _get(path: str, params: dict) -> dict:
    # Límite público de la NVD: 5 peticiones / 30 s (50 con clave).
    limit = 50 if KEY else 5
    now = time.monotonic()
    _last_calls[:] = [t for t in _last_calls if now - t < 30]
    if len(_last_calls) >= limit:
        time.sleep(30 - (now - _last_calls[0]) + 0.5)
    _last_calls.append(time.monotonic())
    url = f"{API}/{path}?{urllib.parse.urlencode(params, safe=':*')}"
    headers = {"User-Agent": "sarezain-cve-lookup"}
    if KEY:
        headers["apiKey"] = KEY
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), context=_CTX, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 3:
                time.sleep(8 * (attempt + 1))  # la NVD frena por exceso de peticiones: esperar y reintentar
                continue
            raise
    raise RuntimeError("NVD no disponible")


def _score(cve: dict) -> tuple[float | None, str | None]:
    m = cve.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            d = m[k][0]["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
    return None, None


def _summary(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "es":
            return d["value"]
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def normalize_version(version: str) -> tuple[str, str]:
    """'8.9p1' -> ('8.9', 'p1'); '2.4.29' -> ('2.4.29', '*')"""
    m = re.match(r"(\d+(?:\.\d+)*)(?:[_\-]?(p\d+|rc\d+|beta\d*|[a-z]\d*))?", version or "")
    if not m:
        return version, "*"
    return m.group(1), (m.group(2) or "*")


def lookup(product: str, version: str) -> dict | None:
    """{'cpe':..., 'total': n, 'cves': [{'id','cvss','summary'}...] } o None si no se puede consultar."""
    key = (product or "").lower().strip()
    candidates = CPE_MAP.get(key)
    if not candidates or not version:
        return None
    if isinstance(candidates, tuple):
        candidates = [candidates]
    vnum, update = normalize_version(version)
    cache_key = f"{key}:{vnum}:{update}"
    cache = _cache()
    hit = cache.get(cache_key)
    if hit and time.time() - hit["ts"] < TTL:
        return hit["data"]

    try:
        names: list[str] = []
        for vendor, prod in candidates:
            found = _get("cpes/2.0", {"cpeMatchString": f"cpe:2.3:a:{vendor}:{prod}:{vnum}", "resultsPerPage": 50})
            names = [p["cpe"]["cpeName"] for p in found.get("products", []) if not p["cpe"].get("deprecated")]
            if names:
                break
        if not names:
            data = {"cpe": None, "total": 0, "cves": []}
        else:
            exact = next((n for n in names if n.split(":")[5] == vnum and n.split(":")[6] in (update, "-" if update == "*" else update)), names[0])
            res = _get("cves/2.0", {"cpeName": exact, "resultsPerPage": 200})
            cves = []
            for v in res.get("vulnerabilities", []):
                c = v["cve"]
                score, vector = _score(c)
                cves.append({"id": c["id"], "cvss": score, "vector": vector, "summary": _summary(c)[:400],
                             "kev": bool(c.get("cisaExploitAdd"))})
            cves.sort(key=lambda x: (x["kev"], x["cvss"] or 0), reverse=True)
            data = {"cpe": exact, "total": res.get("totalResults", len(cves)), "cves": cves[:25]}
    except Exception:
        return None  # sin Internet o NVD caída: el escaneo sigue sin CVE

    cache[cache_key] = {"ts": time.time(), "data": data}
    _save_cache(cache)
    return data
