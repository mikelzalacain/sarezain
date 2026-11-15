"""Genera sarezain/web/demo.json: una red FICTICIA evaluada con el motor real.

Los dispositivos, IPs y MACs son inventados. Las reglas, las soluciones
personalizadas y las CVE (consultadas en la NVD del NIST) son las reales.

Uso:  python tools/make_demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from sarezain import checks, cve, remediation

OUT = Path(__file__).resolve().parent.parent / "sarezain" / "web" / "demo.json"
GW = "192.168.1.1"


def svc(port, service, **kw):
    return {"port": port, "service": service, **kw}


SELF_SIGNED = {"subject": "192.168.1.1", "issuer": "192.168.1.1", "self_signed": True,
               "expires": "2031-03-02T10:00:00+00:00", "expired": False}

HOSTS = [
    dict(ip=GW, mac="A4:B1:C1:3E:21:07", vendor="Askey Computer", hostname="router.home", model="Askey RTF8225VW",
         os="Equipo de red (firmware propio)", is_gateway=True, ttl=64, seen_by=["arp", "ping", "ssdp"],
         upnp={"server": "Linux/3.4 UPnP/1.0 MiniUPnPd/2.1", "location": None},
         services=[svc(53, "DNS"), svc(80, "HTTP", tls=False, status=200, title="Router · Acceso", login_form=True),
                   svc(443, "HTTPS", tls=True, status=200, tls_version="TLSv1.2", cipher="AES128-GCM-SHA256", certificate=SELF_SIGNED)]),
    dict(ip="192.168.1.10", mac="D4:81:D7:5A:90:12", vendor="Dell", hostname="SALON-PC", os="Windows", ttl=128,
         seen_by=["arp", "tcp"], workgroup="WORKGROUP",
         services=[svc(135, "MS-RPC"), svc(139, "NetBIOS"), svc(445, "SMB", smb1=False), svc(3389, "RDP")]),
    dict(ip="192.168.1.11", mac="3C:A9:F4:22:6B:01", vendor="Intel Corporate", hostname="PORTATIL-ANA", os="Windows 10 Pro",
         is_self=True, ttl=128, seen_by=["local"],
         services=[svc(135, "MS-RPC"), svc(139, "NetBIOS"), svc(445, "SMB", smb1=False)]),
    dict(ip="192.168.1.15", mac="52:54:00:9A:1C:3D", vendor=None, hostname="dev-server", os="Linux (Ubuntu)", ttl=64,
         seen_by=["arp", "ping"],
         services=[svc(22, "SSH", banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1", product="OpenSSH", version="8.2p1"),
                   svc(80, "HTTP", tls=False, status=200, title="Proyecto interno", product="Apache", version="2.4.49",
                       headers={"server": "Apache/2.4.49 (Unix)"}),
                   svc(5432, "PostgreSQL")]),
    dict(ip="192.168.1.20", mac="00:11:32:8F:44:A0", vendor="Synology", hostname="DiskStation", model="Synology DS218",
         os="Synology DSM", ttl=64, seen_by=["arp", "ping", "ssdp"], mdns_services=["Archivos compartidos (SMB)", "Web"],
         services=[svc(22, "SSH", banner="SSH-2.0-OpenSSH_7.4", product="OpenSSH", version="7.4"),
                   svc(139, "NetBIOS"), svc(445, "SMB", smb1=True),
                   svc(5000, "HTTP", tls=False, status=200, title="Synology DiskStation", login_form=True),
                   svc(5001, "HTTPS", tls=True, status=200, tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                       certificate={"subject": "synology", "issuer": "Synology Inc. CA", "self_signed": True,
                                    "expires": "2026-02-01T00:00:00+00:00", "expired": True}),
                   svc(32400, "Plex", tls=False, status=401, title=None)]),
    dict(ip="192.168.1.30", mac="C0:56:E3:71:0B:9E", vendor="Hangzhou Hikvision Digital", hostname=None, model="Hikvision DS-2CD2143",
         os="Linux", ttl=64, seen_by=["arp", "ping"],
         services=[svc(23, "Telnet", banner="(none) login:"),
                   svc(80, "HTTP", tls=False, status=200, title="Login", login_form=True, product="lighttpd", version="1.4.35",
                       headers={"server": "lighttpd/1.4.35"}),
                   svc(554, "RTSP (vídeo)")]),
    dict(ip="192.168.1.40", mac="3C:2A:F4:10:5D:88", vendor="Brother Industries", hostname="BRN3C2AF4105D88",
         model="Brother HL-L2350DW", os="Equipo de red (firmware propio)", ttl=255, seen_by=["arp", "ping"],
         mdns_services=["Impresión IPP", "Impresora"],
         services=[svc(80, "HTTP", tls=False, status=200, title="Brother HL-L2350DW series"),
                   svc(443, "HTTPS", tls=True, status=200, tls_version="TLSv1", cipher="AES256-SHA",
                       certificate={"subject": "BRN3C2AF4105D88", "issuer": "BRN3C2AF4105D88", "self_signed": True,
                                    "expires": "2035-01-01T00:00:00+00:00", "expired": False}),
                   svc(631, "IPP (impresora)"), svc(9100, "Impresión RAW")]),
    dict(ip="192.168.1.50", mac="F4:7B:09:3A:C2:15", vendor="Samsung Electronics", hostname="Samsung-TV", model="Samsung QE55Q60",
         os="Linux (Tizen)", ttl=64, seen_by=["arp", "ping", "ssdp"],
         upnp={"server": "SHP, UPnP/1.0, Samsung UPnP SDK/1.0", "location": None},
         services=[svc(8001, "HTTP"), svc(8002, "HTTPS"), svc(9197, "desconocido")]),
    dict(ip="192.168.1.60", mac="DC:A6:32:5E:7F:21", vendor="Raspberry Pi Trading", hostname="homeassistant",
         os="Linux (Raspberry Pi OS)", ttl=64, seen_by=["arp", "ping"], mdns_services=["Web", "SSH"],
         services=[svc(22, "SSH", banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", product="OpenSSH", version="9.2p1"),
                   svc(1883, "MQTT"), svc(6379, "Redis", no_auth=True, banner="+PONG"),
                   svc(8123, "Home Assistant", tls=False, status=200, title="Home Assistant")]),
    dict(ip="192.168.1.70", mac="7A:1F:4C:90:2E:3B", vendor="MAC privada (aleatoria)", hostname="iPhone-de-Ana", os="iOS / iPadOS",
         ttl=64, seen_by=["arp", "ping"], services=[svc(62078, "iPhone sync")]),
    dict(ip="192.168.1.80", mac="2C:FD:A1:77:0C:54", vendor="Xiaomi Communications", hostname="Redmi-Note-12", os="Android", ttl=64,
         seen_by=["arp", "ping"], services=[svc(5555, "ADB (Android)")]),
    dict(ip="192.168.1.90", mac="F4:F5:D8:3B:66:0A", vendor="Google", hostname="Chromecast", model="Google Chromecast",
         os="Linux", ttl=64, seen_by=["arp", "ping"], mdns_services=["Chromecast / Google Cast"],
         services=[svc(8008, "HTTP (Chromecast)"), svc(8009, "Cast")]),
    dict(ip="192.168.1.120", mac="84:F3:EB:2D:91:C4", vendor="Espressif", hostname=None, os=None, ttl=255,
         seen_by=["arp"], new=True, services=[svc(80, "HTTP", tls=False, status=200, title="Smart Plug")]),
]

NET = {
    "wifi": {"ssid": "MOVISTAR_4F2A", "bssid": "a4:b1:c1:3e:21:08", "auth": "WPA2-Personal", "cipher": "CCMP",
             "band": "5 GHz", "channel": "44", "radio": "802.11ax", "signal": "82%", "isp": "Movistar",
             "twins": [{"auth": "Abierta", "bssids": ["02:1a:11:fe:4c:90"]}]},
    "dns": [{"server": GW, "provider": "Router (reenvía al DNS del operador)"}],
    "ipv6": {"global": True, "addresses": ["2a0c:5a80:xxxx::11"]},
    "upnp_igd": {"external_ip": "203.0.113.47", "mappings": [
        {"external_port": 3389, "protocol": "TCP", "internal_ip": "192.168.1.10", "internal_port": 3389,
         "description": "Remote Desktop", "enabled": True},
        {"external_port": 32400, "protocol": "TCP", "internal_ip": "192.168.1.20", "internal_port": 32400,
         "description": "Plex Media Server", "enabled": True}]},
    "arp_anomalies": [],
}

LOCAL = {
    "os": {"caption": "Microsoft Windows 10 Pro", "version": "10.0.19045", "build": 19045},
    "firewall": [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": True}, {"name": "Public", "enabled": True}],
    "defender": {"av": True, "realtime": True, "sig_age": 1, "tamper": True},
    "antivirus": [{"name": "Windows Defender", "state": 397568}],
    "smb": {"smb1": False, "signing": False},
    "rdp_enabled": False, "uac": {"enabled": True, "prompt": 5},
    "last_update": "2026-09-08", "last_update_id": "KB5065429", "guest_enabled": False, "bitlocker": 2,
    "network_category": "Private",
    "listening": [{"port": 135, "process": "svchost"}, {"port": 445, "process": "System"},
                  {"port": 3000, "process": "node"}, {"port": 5040, "process": "svchost"}],
}


def main() -> None:
    ctx = {"gateway": GW, "isp": NET["wifi"]["isp"], "interface": "Wi-Fi"}
    products = {(s["product"], s["version"]) for h in HOSTS for s in h["services"] if s.get("product") and s.get("version")}
    lookups = {}
    for prod, ver in sorted(products):
        lookups[(prod, ver)] = cve.lookup(prod, ver)
        print(f"CVE {prod} {ver}: {lookups[(prod, ver)] and lookups[(prod, ver)]['total']}")

    hosts = []
    for h in HOSTS:
        h = {"mdns_services": [], "upnp": None, "upnp_info": None, "snmp": None, "workgroup": None, "model": None,
             "is_gateway": False, "is_self": False, "new": False, **h}
        for s in h["services"]:
            r = lookups.get((s.get("product"), s.get("version")))
            if r and r.get("cves"):
                s["cve"] = r
        h["type"] = checks.guess_type(h)
        h["findings"] = [remediation.apply(f, h, ctx) for f in checks.evaluate(h)]
        h["risk"] = checks.risk_score(h["findings"])
        h["level"] = checks.risk_level(h["risk"])
        hosts.append(h)

    net_f = [remediation.apply({**f, "scope": "network"}, None, ctx) for f in checks.evaluate_network(NET, hosts)]
    loc_f = [remediation.apply({**f, "scope": "local"}, None, ctx) for f in checks.evaluate_local(LOCAL)]
    all_f = net_f + loc_f + [f for h in hosts for f in h["findings"]]
    risk = max([h["risk"] for h in hosts] + [checks.risk_score(net_f + loc_f)])
    scan = {
        "id": "demo", "started": "2026-11-15T18:30:00", "duration": 34.2, "profile": "completo", "ports_scanned": 1137,
        "network": "192.168.1.0/24",
        "local": {"ip": "192.168.1.11", "prefix": 24, "network": "192.168.1.0/24", "gateway": GW,
                  "mac": "3C:A9:F4:22:6B:01", "interface": "Wi-Fi", "hostname": "PORTATIL-ANA"},
        "hosts": hosts,
        "network_audit": {**NET, "findings": net_f},
        "local_audit": {**LOCAL, "findings": loc_f},
        "summary": {"risk": risk, "level": checks.risk_level(risk), "hosts": len(hosts),
                    "open_ports": sum(len(h["services"]) for h in hosts),
                    "findings": {s: sum(1 for f in all_f if f["severity"] == s) for s in checks.SEVERITY_ORDER},
                    "new_hosts": sum(1 for h in hosts if h["new"]), "cve_errors": 0},
        "demo": True,
    }
    OUT.write_text(json.dumps(scan, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(hosts)} dispositivos, {len(all_f)} hallazgos, riesgo {risk} -> {OUT} ({OUT.stat().st_size // 1024} KB)")
    for h in sorted(hosts, key=lambda x: -x["risk"]):
        print(f"  {h['ip']:<14} {h['type']:<10} {h['level']:<8} " + "; ".join(f["title"] for f in h["findings"]))


if __name__ == "__main__":
    main()
