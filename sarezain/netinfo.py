"""Detección de la red local: IP propia, máscara, puerta de enlace y MAC."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass, asdict

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class LocalNetwork:
    ip: str
    prefix: int
    network: str
    gateway: str | None
    mac: str | None
    interface: str | None
    hostname: str

    def to_dict(self) -> dict:
        return asdict(self)


def _local_ip() -> str:
    # No envía ningún paquete: solo pregunta al sistema qué interfaz usaría.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _run(cmd: list[str], timeout: float = 8) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             creationflags=NO_WINDOW, encoding="utf-8", errors="replace")
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _windows_details(ip: str) -> tuple[int | None, str | None, str | None, str | None]:
    script = (
        f"$a=Get-NetIPAddress -IPAddress '{ip}' -ErrorAction SilentlyContinue | Select-Object -First 1;"
        "if($a){$n=Get-NetAdapter -InterfaceIndex $a.InterfaceIndex;"
        "$g=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue"
        " | Sort-Object RouteMetric | Select-Object -First 1).NextHop;"
        "\"$($a.PrefixLength)|$($n.MacAddress)|$g|$($n.Name)\"}"
    )
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script]).strip()
    if "|" not in out:
        return None, None, None, None
    prefix, mac, gw, name = (out.splitlines()[-1].split("|") + [None] * 4)[:4]
    return (int(prefix) if prefix and prefix.isdigit() else None,
            normalize_mac(mac) if mac else None,
            gw or None, name or None)


def _linux_details(ip: str) -> tuple[int | None, str | None, str | None, str | None]:
    prefix = mac = gw = iface = None
    for line in _run(["ip", "-o", "-f", "inet", "addr", "show"]).splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+" + re.escape(ip) + r"/(\d+)", line)
        if m:
            iface, prefix = m.group(1), int(m.group(2))
    m = re.search(r"default via (\S+)", _run(["ip", "route", "show", "default"]))
    if m:
        gw = m.group(1)
    if iface:
        try:
            with open(f"/sys/class/net/{iface}/address", encoding="ascii") as f:
                mac = normalize_mac(f.read().strip())
        except OSError:
            pass
    return prefix, mac, gw, iface


def normalize_mac(mac: str) -> str:
    hexes = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexes) != 12:
        return mac
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


def detect() -> LocalNetwork:
    ip = _local_ip()
    system = platform.system()
    if system == "Windows":
        prefix, mac, gw, iface = _windows_details(ip)
    elif system == "Linux":
        prefix, mac, gw, iface = _linux_details(ip)
    else:
        prefix = mac = gw = iface = None

    # Por defecto /24; nunca más grande que /22 aunque la interfaz lo sea.
    prefix = max(prefix or 24, 22)
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    if gw is None:
        gw = str(next(net.hosts()))  # suposición habitual: .1
    return LocalNetwork(ip=ip, prefix=prefix, network=str(net), gateway=gw,
                        mac=mac, interface=iface, hostname=socket.gethostname())
