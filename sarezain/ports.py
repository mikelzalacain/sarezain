"""Escaneo de puertos TCP (connect scan: no necesita permisos de administrador)."""

from __future__ import annotations

import asyncio

# Puerto -> nombre del servicio. Seleccionados por ser habituales en redes domésticas
# y pymes, o por ser un riesgo cuando están expuestos.
SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    81: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 515: "LPD (impresora)",
    548: "AFP", 554: "RTSP (vídeo)", 587: "SMTP", 631: "IPP (impresora)",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "SQL Server", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT",
    1900: "UPnP", 2049: "NFS", 2375: "Docker API", 2376: "Docker API (TLS)",
    3000: "HTTP (dev)", 3306: "MySQL", 3389: "RDP", 5000: "HTTP", 5001: "HTTPS",
    5060: "SIP", 5353: "mDNS", 5432: "PostgreSQL", 5555: "ADB (Android)",
    5900: "VNC", 5901: "VNC", 6379: "Redis", 7547: "TR-069", 8000: "HTTP",
    8008: "HTTP (Chromecast)", 8009: "Cast", 8080: "HTTP", 8081: "HTTP",
    8443: "HTTPS", 8888: "HTTP", 9000: "HTTP", 9090: "HTTP", 9100: "Impresión RAW",
    9200: "Elasticsearch", 9443: "HTTPS", 10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 32400: "Plex", 49152: "UPnP", 62078: "iPhone sync",
}

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 10000, 32400, 49152}
HTTPS_PORTS = {443, 5001, 8443, 9443}


async def scan_host(ip: str, sem: asyncio.Semaphore, timeout: float = 0.8) -> list[int]:
    async def check(port: int) -> int | None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            except (OSError, asyncio.TimeoutError):
                return None
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, asyncio.TimeoutError):
                pass
            return port
    results = await asyncio.gather(*(check(p) for p in SERVICES))
    return sorted(p for p in results if p)
