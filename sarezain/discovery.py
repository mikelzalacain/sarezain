"""Descubrimiento de dispositivos: barrido ping + sondas TCP + tabla ARP + SSDP."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .netinfo import NO_WINDOW, normalize_mac

IS_WINDOWS = platform.system() == "Windows"
_POOL = ThreadPoolExecutor(max_workers=64, thread_name_prefix="sarezain")

# Puertos rápidos para encontrar equipos que no responden a ping (p. ej. Windows con firewall).
PROBE_PORTS = (80, 443, 445, 22, 139, 3389, 8080, 62078, 8008, 554)


def _ping(ip: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "700", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4,
                             creationflags=NO_WINDOW, encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return False
    # En Windows "host inaccesible" también devuelve 0: se exige TTL en la respuesta.
    return out.returncode == 0 and "ttl=" in out.stdout.lower()


async def _tcp_alive(ip: str, sem: asyncio.Semaphore) -> bool:
    async def one(port: int) -> bool:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 0.6)
                w.close()
                return True
            except ConnectionRefusedError:
                return True  # un RST también demuestra que el equipo existe
            except (OSError, asyncio.TimeoutError):
                return False
    results = await asyncio.gather(*(one(p) for p in PROBE_PORTS))
    return any(results)


def read_arp_table() -> dict[str, str]:
    """IP -> MAC según la caché ARP del sistema."""
    cmd = ["arp", "-a"] if IS_WINDOWS else ["ip", "neigh"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                             creationflags=NO_WINDOW, encoding="utf-8", errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table = {}
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\D+?((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", out):
        mac = normalize_mac(m.group(2))
        first = int(mac[:2], 16)
        if mac == "FF:FF:FF:FF:FF:FF" or first & 0x01:  # broadcast / multicast
            continue
        table[m.group(1)] = mac
    return table


def _reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return None if name == ip else name
    except (OSError, UnicodeError):
        return None


async def resolve_names(ips: list[str]) -> dict[str, str]:
    loop = asyncio.get_running_loop()

    async def one(ip: str):
        try:
            return ip, await asyncio.wait_for(loop.run_in_executor(_POOL, _reverse_dns, ip), 3)
        except asyncio.TimeoutError:
            return ip, None
    return {ip: name for ip, name in await asyncio.gather(*(one(i) for i in ips)) if name}


def ssdp_discover(timeout: float = 2.5) -> dict[str, dict]:
    """Envía un M-SEARCH UPnP a la red local y devuelve quién responde."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found: dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            text = data.decode("utf-8", errors="replace")
            server = re.search(r"(?im)^server:\s*(.+)$", text)
            location = re.search(r"(?im)^location:\s*(.+)$", text)
            entry = found.setdefault(ip, {"server": None, "location": None})
            entry["server"] = entry["server"] or (server.group(1).strip() if server else None)
            entry["location"] = entry["location"] or (location.group(1).strip() if location else None)
    finally:
        s.close()
    return found


async def discover(network: ipaddress.IPv4Network, progress=None) -> dict[str, dict]:
    """Devuelve {ip: {"mac":..., "via": [...]}} de los equipos vivos."""
    loop = asyncio.get_running_loop()
    hosts = [str(h) for h in network.hosts()]
    alive: dict[str, set] = {}
    done = 0

    async def ping(ip: str):
        nonlocal done
        if await loop.run_in_executor(_POOL, _ping, ip):
            alive.setdefault(ip, set()).add("ping")
        done += 1
        if progress and done % 8 == 0:
            progress(done / len(hosts) * 0.5)

    ssdp_task = loop.run_in_executor(_POOL, ssdp_discover)
    await asyncio.gather(*(ping(ip) for ip in hosts))

    # Segunda pasada por TCP solo para los que no respondieron a ping.
    sem = asyncio.Semaphore(256)
    pending = [ip for ip in hosts if ip not in alive]
    done = 0

    async def tcp(ip: str):
        nonlocal done
        if await _tcp_alive(ip, sem):
            alive.setdefault(ip, set()).add("tcp")
        done += 1
        if progress and done % 8 == 0:
            progress(0.5 + done / max(len(pending), 1) * 0.5)

    await asyncio.gather(*(tcp(ip) for ip in pending))

    arp = read_arp_table()
    for ip in arp:
        if ipaddress.ip_address(ip) in network and ip != str(network.broadcast_address):
            alive.setdefault(ip, set()).add("arp")

    ssdp = await ssdp_task
    for ip in ssdp:
        if ipaddress.ip_address(ip) in network:
            alive.setdefault(ip, set()).add("ssdp")

    return {ip: {"mac": arp.get(ip), "via": sorted(via), "ssdp": ssdp.get(ip)}
            for ip, via in alive.items()}
