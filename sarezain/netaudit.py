"""Auditoría de la red en sí: Wi-Fi, DNS, puertos abiertos a Internet (UPnP), ARP e IPv6."""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import urllib.request
from collections import defaultdict

from .netinfo import NO_WINDOW

IS_WINDOWS = platform.system() == "Windows"

# Prefijos de SSID de fábrica de operadores habituales en España.
ISP_SSIDS = {
    "vodafone": "Vodafone", "movistar_": "Movistar", "mifibra-": "Movistar", "orange-": "Orange",
    "jazztel_": "Jazztel", "digifibra": "Digi", "o2-": "O2", "masmovil": "MásMóvil", "lowi": "Lowi",
    "yoigo": "Yoigo", "pepephone": "Pepephone", "euskaltel": "Euskaltel", "wlan_": "Movistar",
    "simyo": "Simyo", "adamo": "Adamo", "virgin": "Virgin telco",
}
KNOWN_DNS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare (anti-malware)",
    "1.0.0.2": "Cloudflare (anti-malware)", "1.1.1.3": "Cloudflare (familias)",
    "8.8.8.8": "Google", "8.8.4.4": "Google", "9.9.9.9": "Quad9 (anti-malware)", "149.112.112.112": "Quad9 (anti-malware)",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
}
RISKY_FORWARDS = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "Escritorio remoto", 5900: "VNC", 3306: "MySQL",
                  1433: "SQL Server", 5432: "PostgreSQL", 6379: "Redis", 21: "FTP", 554: "Cámara (RTSP)", 8080: "Web"}


def _run(cmd: list[str] | str, timeout: float = 10, shell: bool = False) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, shell=shell,
                              creationflags=NO_WINDOW).stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def _netsh(args: str) -> str:
    return _run(f"chcp 65001 >nul & netsh {args}", shell=True)


def _field(block: str, *keys: str) -> str | None:
    for k in keys:
        m = re.search(rf"^\s*{k}\s*:\s*(.+?)\s*$", block, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1)
    return None


def wifi() -> dict | None:
    if not IS_WINDOWS:
        return None
    out = _netsh("wlan show interfaces")
    blocks = re.split(r"\n\s*\n", out)
    for b in blocks:
        state = (_field(b, "Estado", "State") or "").lower()
        if "conectado" in state and "desconectado" not in state or state == "connected":
            ssid = _field(b, "SSID")
            info = {
                "ssid": ssid,
                "bssid": _field(b, "AP BSSID", "BSSID"),
                "auth": _field(b, "Autenticación", "Authentication"),
                "cipher": _field(b, "Cifrado", "Cipher"),
                "band": _field(b, "Banda", "Band"),
                "channel": _field(b, "Canal", "Channel"),
                "radio": _field(b, "Tipo de radio", "Radio type"),
                "signal": _field(b, "Señal", "Signal"),
            }
            info["isp"] = next((name for p, name in ISP_SSIDS.items() if (ssid or "").lower().startswith(p)), None)
            info["twins"] = _twins(ssid, info["auth"], info["bssid"])
            return info
    return None


def _twins(ssid: str | None, auth: str | None, my_bssid: str | None) -> list[dict]:
    """Otras redes cercanas con el MISMO nombre pero distinta seguridad (posible 'gemelo malvado')."""
    if not ssid:
        return []
    out = _netsh("wlan show networks mode=bssid")
    suspicious = []
    for block in re.split(r"(?=^SSID \d+ :)", out, flags=re.MULTILINE):
        m = re.match(r"SSID \d+ :\s*(.*)", block)
        if not m or m.group(1).strip() != ssid:
            continue
        net_auth = _field(block, "Autenticación", "Authentication")
        if net_auth and auth and net_auth != auth:
            bssids = re.findall(r"BSSID \d+\s*:\s*([0-9a-f:]{17})", block, re.IGNORECASE)
            suspicious.append({"auth": net_auth, "bssids": [b for b in bssids if b != my_bssid]})
    return suspicious


def dns_servers(local_ip: str, gateway: str | None) -> list[dict]:
    servers: list[str] = []
    if IS_WINDOWS:
        script = (f"$i=(Get-NetIPAddress -IPAddress '{local_ip}' -ErrorAction SilentlyContinue).InterfaceIndex;"
                  "(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ','")
        servers = [s for s in _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script]).strip().split(",") if s]
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                servers = re.findall(r"^nameserver\s+(\S+)", f.read(), re.MULTILINE)
        except OSError:
            pass
    result = []
    for s in servers:
        if s == gateway:
            kind = "Router (reenvía al DNS del operador)"
        elif s in KNOWN_DNS:
            kind = KNOWN_DNS[s]
        else:
            try:
                kind = "Red local" if ipaddress.ip_address(s).is_private else "DNS del operador u otro"
            except ValueError:
                kind = "Desconocido"
        result.append({"server": s, "provider": kind})
    return result


def _soap(control_url: str, service: str, action: str, args: str = "") -> str | None:
    body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>').encode()
    req = urllib.request.Request(control_url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.read(100_000).decode("utf-8", errors="replace")
    except Exception:
        return None


def upnp_port_mappings(igd: dict) -> dict:
    """Lista los puertos que el router tiene abiertos hacia Internet mediante UPnP (solo lectura)."""
    ctrl, svc = igd["control"], igd["service"]
    ext = _soap(ctrl, svc, "GetExternalIPAddress")
    ext_ip = re.search(r"<NewExternalIPAddress>([^<]*)<", ext or "")
    mappings = []
    for i in range(64):
        xml = _soap(ctrl, svc, "GetGenericPortMappingEntry", f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
        if not xml or "NewExternalPort" not in xml:
            break
        get = lambda tag: (re.search(rf"<{tag}>([^<]*)<", xml) or [None, None])[1]  # noqa: E731
        mappings.append({
            "external_port": int(get("NewExternalPort") or 0), "protocol": get("NewProtocol"),
            "internal_ip": get("NewInternalClient"), "internal_port": int(get("NewInternalPort") or 0),
            "description": get("NewPortMappingDescription"), "enabled": get("NewEnabled") in ("1", "true"),
        })
    return {"external_ip": ext_ip.group(1) if ext_ip else None, "mappings": mappings}


def arp_anomalies(arp: dict[str, str], gateway: str | None) -> list[dict]:
    """Varias IP con la misma MAC (incluida la del router) puede indicar suplantación ARP."""
    by_mac: dict[str, list[str]] = defaultdict(list)
    for ip, mac in arp.items():
        by_mac[mac].append(ip)
    out = []
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            out.append({"mac": mac, "ips": sorted(ips), "involves_gateway": gateway in ips})
    return out


def ipv6_status() -> dict:
    if not IS_WINDOWS:
        return {"global": False}
    script = ("Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
              "Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -notlike '::1' } | "
              "Select-Object -ExpandProperty IPAddress")
    addrs = [a.strip() for a in _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script]).splitlines() if a.strip()]
    glob = [a for a in addrs if ipaddress.ip_address(a.split("%")[0]).is_global]
    return {"global": bool(glob), "addresses": glob[:3]}
