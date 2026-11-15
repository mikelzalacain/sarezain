"""Identificación profunda: mDNS/Bonjour, NetBIOS, descripción UPnP, SNMP y sistema operativo.

Sirve para saber QUÉ es cada dispositivo (modelo, nombre, sistema) y así dar
soluciones adaptadas a él.
"""

from __future__ import annotations

import ipaddress
import random
import re
import socket
import struct
import urllib.request
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------- DNS mínimo


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while offset < len(data) and depth < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # puntero de compresión
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if jumped_end is None:
                jumped_end = offset + 2
            offset = ptr
            depth += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), (jumped_end if jumped_end is not None else offset)


def _parse_dns(data: bytes) -> list[dict]:
    """Devuelve todos los registros (respuestas + autoridad + adicionales)."""
    if len(data) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    records = []
    for _ in range(an + ns + ar):
        if off >= len(data):
            break
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rec = {"name": name, "type": rtype}
        if rtype == 12:  # PTR
            rec["value"] = _read_name(data, off)[0]
        elif rtype == 1 and rdlen == 4:  # A
            rec["value"] = socket.inet_ntoa(rdata)
        elif rtype == 16:  # TXT
            txt, i = {}, 0
            while i < len(rdata):
                ln = rdata[i]
                item = rdata[i + 1:i + 1 + ln].decode("utf-8", errors="replace")
                if "=" in item:
                    k, v = item.split("=", 1)
                    txt[k.lower()] = v
                i += 1 + ln
            rec["value"] = txt
        elif rtype == 33 and rdlen > 6:  # SRV
            rec["value"] = _read_name(data, off + 6)[0]
        records.append(rec)
        off += rdlen
    return records


# ---------------------------------------------------------------- mDNS / Bonjour

MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_device-info._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local",
    "_printer._tcp.local", "_pdl-datastream._tcp.local", "_scanner._tcp.local",
    "_smb._tcp.local", "_afpovertcp._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
    "_http._tcp.local", "_workstation._tcp.local", "_hap._tcp.local", "_homekit._tcp.local",
    "_matter._tcp.local", "_spotify-connect._tcp.local", "_amzn-wplay._tcp.local",
    "_companion-link._tcp.local", "_sleep-proxy._udp.local", "_androidtvremote2._tcp.local",
    "_nvstream._tcp.local", "_sonos._tcp.local", "_esphomelib._tcp.local", "_hue._tcp.local",
]

MDNS_LABELS = {
    "_airplay": "AirPlay", "_raop": "AirPlay audio", "_googlecast": "Chromecast / Google Cast",
    "_ipp": "Impresión IPP", "_ipps": "Impresión IPP", "_printer": "Impresora", "_pdl-datastream": "Impresora",
    "_scanner": "Escáner", "_smb": "Archivos compartidos (SMB)", "_afpovertcp": "Archivos compartidos (AFP)",
    "_ssh": "SSH", "_sftp-ssh": "SFTP", "_http": "Web", "_workstation": "Equipo de trabajo",
    "_hap": "HomeKit", "_homekit": "HomeKit", "_matter": "Matter (domótica)", "_spotify-connect": "Spotify Connect",
    "_amzn-wplay": "Amazon Fire TV", "_companion-link": "Dispositivo Apple", "_androidtvremote2": "Android TV",
    "_nvstream": "NVIDIA GameStream", "_sonos": "Sonos", "_esphomelib": "ESPHome", "_hue": "Philips Hue",
}


def _mdns_query(names: list[str]) -> bytes:
    pkt = struct.pack("!6H", 0, 0, len(names), 0, 0, 0)
    for n in names:
        for label in n.split("."):
            pkt += bytes([len(label)]) + label.encode()
        pkt += b"\x00" + struct.pack("!HH", 12, 0x8001)  # PTR, IN + bit QU (respuesta unicast)
    return pkt


def mdns_browse(network: ipaddress.IPv4Network, timeout: float = 3.0) -> dict[str, dict]:
    """IP -> {"name", "services": [...], "model", "txt": {...}}"""
    found: dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.settimeout(timeout)
        query = _mdns_query(MDNS_SERVICES[:14]), _mdns_query(MDNS_SERVICES[14:])
        for q in query:
            s.sendto(q, ("224.0.0.251", 5353))
        while True:
            try:
                data, (ip, _) = s.recvfrom(9000)
            except (socket.timeout, OSError):
                break
            if ipaddress.ip_address(ip) not in network:
                continue
            entry = found.setdefault(ip, {"name": None, "services": set(), "model": None, "txt": {}})
            for rec in _parse_dns(data):
                name = rec["name"]
                if rec["type"] == 12:
                    svc = rec["name"].split(".")[0]
                    if svc in MDNS_LABELS:
                        entry["services"].add(MDNS_LABELS[svc])
                    inst = rec["value"].split("._")[0]
                    if inst and not inst.startswith("_") and not entry["name"]:
                        entry["name"] = inst
                elif rec["type"] == 16 and isinstance(rec.get("value"), dict):
                    txt = rec["value"]
                    entry["txt"].update({k: v for k, v in txt.items() if k in ("md", "model", "fn", "ty", "am", "osxvers", "srcvers", "manufacturer", "product")})
                    model = txt.get("md") or txt.get("model") or txt.get("am") or txt.get("ty") or txt.get("product")
                    if model and not entry["model"]:
                        entry["model"] = model
                    if txt.get("fn"):
                        entry["name"] = txt["fn"]
                elif rec["type"] == 1 and name.endswith(".local") and not entry["name"] and rec.get("value") == ip:
                    entry["name"] = name[:-6]
    finally:
        s.close()
    for e in found.values():
        e["services"] = sorted(e["services"])
    return found


# ---------------------------------------------------------------- NetBIOS (nombres Windows/Samba)

_NBSTAT = struct.pack("!6H", 0x5A17, 0, 1, 0, 0, 0) + b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00" + struct.pack("!HH", 0x21, 1)


def netbios_names(ips: list[str], timeout: float = 2.0) -> dict[str, dict]:
    """Consulta NBSTAT (UDP 137) a todos los equipos a la vez."""
    out: dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        for ip in ips:
            try:
                s.sendto(_NBSTAT, (ip, 137))
            except OSError:
                pass
        while True:
            try:
                data, (ip, _) = s.recvfrom(2048)
            except (socket.timeout, OSError):
                break
            if len(data) < 57:
                continue
            count = data[56]
            name = group = None
            for i in range(count):
                off = 57 + i * 18
                raw = data[off:off + 15].decode("ascii", errors="replace").strip()
                suffix, flags = data[off + 15], struct.unpack("!H", data[off + 16:off + 18])[0]
                is_group = bool(flags & 0x8000)
                if suffix == 0x00 and not is_group and not name:
                    name = raw
                elif suffix == 0x00 and is_group and not group:
                    group = raw
            if name:
                out[ip] = {"name": name, "workgroup": group}
    finally:
        s.close()
    return out


# ---------------------------------------------------------------- descripción UPnP

def ssdp_describe(location: str, network: ipaddress.IPv4Network) -> dict | None:
    """Lee el XML de descripción UPnP (modelo, fabricante, firmware y servicios IGD)."""
    m = re.match(r"https?://([\d.]+)(?::\d+)?/", location or "")
    if not m or ipaddress.ip_address(m.group(1)) not in network:
        return None  # nunca seguimos URLs fuera de la red local
    try:
        with urllib.request.urlopen(location, timeout=3) as resp:
            xml = resp.read(200_000)
        root = ET.fromstring(xml)
    except Exception:
        return None
    ns = {"u": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}

    def find(el, tag):
        node = el.find(f"u:{tag}", ns) if ns else el.find(tag)
        return node.text.strip() if node is not None and node.text else None

    dev = root.find("u:device", ns) if ns else root.find("device")
    if dev is None:
        return None
    info = {k: find(dev, k) for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription")}
    base = re.match(r"(https?://[^/]+)", location).group(1)
    igd = None
    for svc in root.iter(f"{{{ns['u']}}}service" if ns else "service"):
        stype = find(svc, "serviceType") or ""
        if "WANIPConnection" in stype or "WANPPPConnection" in stype:
            ctrl = find(svc, "controlURL") or ""
            igd = {"service": stype, "control": ctrl if ctrl.startswith("http") else base + "/" + ctrl.lstrip("/")}
    info["igd"] = igd
    return {k: v for k, v in info.items() if v}


# ---------------------------------------------------------------- SNMP

def _snmp_get_sysdescr(community: str = "public") -> tuple[bytes, int]:
    reqid = random.randint(1, 0x7FFFFFFF)
    oid = bytes.fromhex("2b06010201010100")  # 1.3.6.1.2.1.1.1.0 sysDescr
    varbind = b"\x30" + bytes([len(oid) + 4]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
    vbl = b"\x30" + bytes([len(varbind)]) + varbind
    pdu_body = b"\x02\x04" + struct.pack("!I", reqid) + b"\x02\x01\x00\x02\x01\x00" + vbl
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    comm = community.encode()
    body = b"\x02\x01\x00" + b"\x04" + bytes([len(comm)]) + comm + pdu
    return b"\x30" + bytes([len(body)]) + body, reqid


def snmp_public(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    """Devuelve las IP que responden a SNMP con la comunidad por defecto 'public' (solo lectura de sysDescr)."""
    pkt, _ = _snmp_get_sysdescr()
    out: dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        for ip in ips:
            try:
                s.sendto(pkt, (ip, 161))
            except OSError:
                pass
        while True:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            idx = data.find(bytes.fromhex("2b06010201010100"))
            if idx >= 0 and idx + 10 <= len(data) and data[idx + 8] == 0x04:
                ln = data[idx + 9]
                start = idx + 10
                if ln & 0x80:
                    nbytes = ln & 0x7F
                    ln = int.from_bytes(data[start:start + nbytes], "big")
                    start += nbytes
                out[ip] = data[start:start + ln].decode("utf-8", errors="replace").strip()[:200]
    finally:
        s.close()
    return out


# ---------------------------------------------------------------- sistema operativo

def guess_os(host: dict) -> str | None:
    ports = {s["port"] for s in host.get("services", [])}
    hints = " ".join(filter(None, [
        host.get("model"), host.get("hostname"), host.get("vendor"),
        (host.get("upnp_info") or {}).get("modelName"), (host.get("upnp") or {}).get("server"),
        host.get("snmp"), *[str(s.get("banner") or "") + " " + str(s.get("product") or "") for s in host.get("services", [])],
    ])).lower()
    ttl = host.get("ttl")

    if host.get("is_self"):
        return host.get("self_os") or "Windows"
    if any(k in hints for k in ("macbook", "imac", "macmini", "mac mini", "osxvers")):
        return "macOS"
    if any(k in hints for k in ("iphone", "ipad")) or 62078 in ports:
        return "iOS / iPadOS"
    if "android" in hints:
        return "Android"
    if "synology" in hints or "dsm" in hints:
        return "Synology DSM"
    if "qnap" in hints:
        return "QNAP QTS"
    if "raspbian" in hints or "raspberry" in hints:
        return "Linux (Raspberry Pi OS)"
    if "ubuntu" in hints:
        return "Linux (Ubuntu)"
    if "debian" in hints:
        return "Linux (Debian)"
    if ports & {135, 3389} or (ttl and 65 <= ttl <= 128 and ports & {139, 445}):
        return "Windows"
    if "linux" in hints or "openwrt" in hints:
        return "Linux"
    if ttl and ttl > 128:
        return "Equipo de red (firmware propio)"
    if ttl and 32 < ttl <= 64:
        return "Linux / Unix"
    if ttl and 64 < ttl <= 128:
        return "Windows"
    return None
