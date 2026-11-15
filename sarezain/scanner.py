"""Orquestador del escaneo.

Fases: descubrimiento → identificación → puertos → servicios → CVE → red y equipo → evaluación.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Callable

from . import (checks, cve, discovery, hostaudit, identify, netaudit, netinfo, ports, probes,
               remediation, safety, storage, vendors)

PHASES = [
    ("discovery", "Buscando dispositivos", 0.00, 0.22),
    ("identify", "Identificando dispositivos", 0.22, 0.30),
    ("ports", "Escaneando puertos", 0.30, 0.68),
    ("services", "Analizando servicios", 0.68, 0.80),
    ("cve", "Consultando vulnerabilidades (CVE)", 0.80, 0.90),
    ("network", "Auditando la red y este equipo", 0.90, 0.98),
    ("evaluate", "Evaluando riesgos", 0.98, 1.00),
]

ProgressFn = Callable[[str, str, float], None]


async def run_scan(network: str | None = None, on_progress: ProgressFn | None = None,
                   profile: str = "completo", check_cves: bool = True) -> dict:
    local = netinfo.detect()
    net = safety.validate_network(network or local.network)
    port_list = ports.PROFILES.get(profile, ports.PROFILES["completo"])
    started = datetime.now()
    t0 = time.monotonic()
    loop = asyncio.get_running_loop()

    def phase(key: str):
        _, label, start, end = next(p for p in PHASES if p[0] == key)

        def report(fraction: float):
            if on_progress:
                on_progress(key, label, start + (end - start) * min(max(fraction, 0), 1))
        report(0)
        return report

    # 1. Descubrimiento
    report = phase("discovery")
    found = await discovery.discover(net, report)
    if local.ip not in found:
        found[local.ip] = {"mac": local.mac, "via": ["local"], "ssdp": None, "ttl": 128}
    ips = list(found)

    # 2. Identificación (en paralelo; todo es UDP con timeouts cortos)
    report = phase("identify")
    names_t = discovery.resolve_names(ips)
    mdns_t = loop.run_in_executor(None, identify.mdns_browse, net)
    nb_t = loop.run_in_executor(None, identify.netbios_names, ips)
    snmp_t = loop.run_in_executor(None, identify.snmp_public, ips)
    local_t = loop.run_in_executor(None, hostaudit.audit)  # lento (PowerShell): lo lanzamos ya
    names, mdns, nbns, snmp = await asyncio.gather(names_t, mdns_t, nb_t, snmp_t)
    upnp_info = {}
    for ip, info in found.items():
        if info.get("ssdp") and info["ssdp"].get("location"):
            upnp_info[ip] = await loop.run_in_executor(None, identify.ssdp_describe, info["ssdp"]["location"], net)
    report(1)

    # 3. Puertos
    report = phase("ports")
    sem = asyncio.Semaphore(500)
    open_ports: dict[str, list[int]] = {}
    done = 0

    async def scan(ip: str):
        nonlocal done
        open_ports[ip] = await ports.scan_host(ip, sem, port_list=port_list)
        done += 1
        report(done / len(found))

    await asyncio.gather(*(scan(ip) for ip in found))

    # Segunda pasada, más lenta, para los puertos importantes que no respondieron:
    # con miles de conexiones a la vez algunos equipos (routers sobre todo) descartan peticiones.
    slow_sem = asyncio.Semaphore(60)
    important = ports.PROFILES["rapido"]

    async def recheck(ip: str):
        missing = [p for p in important if p not in open_ports[ip]]
        extra = await ports.scan_host(ip, slow_sem, timeout=1.5, port_list=missing)
        open_ports[ip] = sorted(set(open_ports[ip]) | set(extra))

    await asyncio.gather(*(recheck(ip) for ip in found))

    # 4. Servicios
    report = phase("services")
    targets = [(ip, p) for ip, ps in open_ports.items() for p in ps]
    probe_sem = asyncio.Semaphore(48)
    service_info: dict[str, list[dict]] = {ip: [] for ip in found}
    done = 0

    async def probe(ip: str, port: int):
        nonlocal done
        async with probe_sem:
            service_info[ip].append(await probes.probe_port(ip, port))
        done += 1
        report(done / max(len(targets), 1))

    await asyncio.gather(*(probe(ip, p) for ip, p in targets))

    # 5. CVE por producto y versión (solo se envía producto+versión a la NVD)
    report = phase("cve")
    cve_errors = 0
    if check_cves:
        products = sorted({(s["product"], s["version"]) for lst in service_info.values() for s in lst
                           if s.get("product") and s.get("version") and s["product"].lower() in cve.CPE_MAP})
        results = {}
        for i, (prod, ver) in enumerate(products):
            res = await loop.run_in_executor(None, cve.lookup, prod, ver)
            if res is None:
                cve_errors += 1
            results[(prod, ver)] = res
            report((i + 1) / len(products))
        for lst in service_info.values():
            for s in lst:
                r = results.get((s.get("product"), s.get("version")))
                if r and r.get("cves"):
                    s["cve"] = r

    # 6. Red y este equipo
    report = phase("network")
    wifi = await loop.run_in_executor(None, netaudit.wifi)
    dns = await loop.run_in_executor(None, netaudit.dns_servers, local.ip, local.gateway)
    ipv6 = await loop.run_in_executor(None, netaudit.ipv6_status)
    arp = discovery.read_arp_table()
    igd = next((u["igd"] for u in upnp_info.values() if u and u.get("igd")), None)
    upnp_igd = await loop.run_in_executor(None, netaudit.upnp_port_mappings, igd) if igd else None
    local_audit = await local_t
    report(1)

    # 7. Evaluación
    phase("evaluate")
    previous = storage.latest(str(net))
    known = {h.get("mac") or h["ip"] for h in previous["hosts"]} if previous else set()
    # Memoria de identificación: lo aprendido en escaneos anteriores (por MAC) completa
    # lo que esta vez no respondió (mDNS/UPnP son UDP y a veces se pierden).
    memory = {h["mac"]: h for h in (previous or {}).get("hosts", []) if h.get("mac")}
    ctx = {"gateway": local.gateway, "isp": (wifi or {}).get("isp"), "interface": local.interface}

    hosts = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        info = found[ip]
        mac = info.get("mac") or (local.mac if ip == local.ip else None)
        md = mdns.get(ip) or {}
        nb = nbns.get(ip) or {}
        up = upnp_info.get(ip) or {}
        host = {
            "ip": ip,
            "mac": mac,
            "vendor": vendors.lookup(mac),
            "hostname": names.get(ip) or nb.get("name") or md.get("name") or up.get("friendlyName")
                        or (local.hostname if ip == local.ip else None),
            "model": md.get("model") or (" ".join(filter(None, [up.get("manufacturer"), up.get("modelNumber") or up.get("modelName")])) or None),
            "workgroup": nb.get("workgroup"),
            "mdns_services": md.get("services") or [],
            "upnp_info": {k: v for k, v in up.items() if k != "igd"} or None,
            "snmp": snmp.get(ip),
            "ttl": info.get("ttl"),
            "is_gateway": ip == local.gateway,
            "is_self": ip == local.ip,
            "seen_by": info.get("via", []),
            "upnp": info.get("ssdp"),
            "services": sorted(service_info[ip], key=lambda s: s["port"]),
            "new": bool(previous) and (mac or ip) not in known,
        }
        old = memory.get(mac) if mac else None
        if old:
            for key in ("model", "upnp_info", "workgroup"):
                if not host.get(key) and old.get(key):
                    host[key] = old[key]
            if not host["mdns_services"] and old.get("mdns_services"):
                host["mdns_services"] = old["mdns_services"]
        if host["is_self"] and local_audit:
            host["self_os"] = (local_audit.get("os") or {}).get("caption")
        host["os"] = identify.guess_os(host)
        host["type"] = checks.guess_type(host)
        host["findings"] = [remediation.apply(f, host, ctx) for f in checks.evaluate(host)]
        host["risk"] = checks.risk_score(host["findings"])
        host["level"] = checks.risk_level(host["risk"])
        hosts.append(host)

    net_data = {"wifi": wifi, "dns": dns, "ipv6": ipv6, "upnp_igd": upnp_igd,
                "arp_anomalies": netaudit.arp_anomalies(arp, local.gateway)}
    net_findings = [remediation.apply({**f, "scope": "network"}, None, ctx) for f in checks.evaluate_network(net_data, hosts)]
    local_findings = [remediation.apply({**f, "scope": "local"}, None, ctx) for f in checks.evaluate_local(local_audit)]

    all_findings = net_findings + local_findings + [f for h in hosts for f in h["findings"]]
    counts = {sev: sum(1 for f in all_findings if f["severity"] == sev) for sev in checks.SEVERITY_ORDER}
    net_risk = checks.risk_score(net_findings + local_findings)
    risk = max([h["risk"] for h in hosts] + [net_risk])

    scan = {
        "id": started.strftime("%Y%m%d-%H%M%S"),
        "started": started.isoformat(timespec="seconds"),
        "duration": round(time.monotonic() - t0, 1),
        "profile": profile,
        "ports_scanned": len(port_list),
        "network": str(net),
        "local": local.to_dict(),
        "hosts": hosts,
        "network_audit": {**net_data, "findings": net_findings},
        "local_audit": {**(local_audit or {}), "findings": local_findings} if local_audit else None,
        "summary": {
            "risk": risk,
            "level": checks.risk_level(risk),
            "hosts": len(hosts),
            "open_ports": sum(len(h["services"]) for h in hosts),
            "findings": counts,
            "new_hosts": sum(1 for h in hosts if h["new"]),
            "cve_errors": cve_errors,
        },
        "demo": False,
    }
    storage.save(scan)
    if on_progress:
        on_progress("done", "Completado", 1.0)
    return scan
