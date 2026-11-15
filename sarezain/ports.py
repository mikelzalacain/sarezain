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


EXTRA_HIGH_PORTS = [
    1080, 1194, 1433, 1521, 1723, 1883, 1900, 2000, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376,
    3000, 3128, 3268, 3306, 3389, 3690, 4000, 4443, 4444, 4567, 4848, 5000, 5001, 5005, 5060, 5061, 5222,
    5353, 5357, 5432, 5555, 5601, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 7000,
    7001, 7070, 7443, 7547, 7777, 8000, 8001, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8082,
    8083, 8086, 8088, 8090, 8096, 8123, 8181, 8200, 8291, 8333, 8443, 8500, 8728, 8834, 8880, 8888, 8899,
    9000, 9001, 9042, 9080, 9090, 9091, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672,
    20000, 27017, 28017, 32400, 37777, 49152, 49153, 50000, 50070, 55000, 55443, 62078,
]
EXTRA_NAMES = {
    2082: "cPanel", 2083: "cPanel", 2222: "SSH alternativo", 3128: "Proxy", 4444: "Metasploit/backdoor",
    5357: "WSD", 5601: "Kibana", 5672: "RabbitMQ", 5984: "CouchDB", 5985: "WinRM", 5986: "WinRM (TLS)",
    6443: "Kubernetes API", 6667: "IRC", 8086: "InfluxDB", 8096: "Jellyfin", 8123: "Home Assistant",
    8291: "MikroTik Winbox", 8728: "MikroTik API", 8834: "Nessus", 9042: "Cassandra", 9091: "Transmission",
    9418: "Git", 10250: "Kubelet", 15672: "RabbitMQ admin", 37777: "DVR Dahua", 55000: "UPnP/DLNA",
}

PROFILES = {
    "rapido": sorted(SERVICES),
    "completo": sorted(set(range(1, 1025)) | set(SERVICES) | set(EXTRA_HIGH_PORTS)),
}


def service_name(port: int) -> str:
    return SERVICES.get(port) or EXTRA_NAMES.get(port) or "desconocido"


async def scan_host(ip: str, sem: asyncio.Semaphore, timeout: float = 0.8, port_list: list[int] | None = None) -> list[int]:
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
    results = await asyncio.gather(*(check(p) for p in (port_list or SERVICES)))
    return sorted(p for p in results if p)
