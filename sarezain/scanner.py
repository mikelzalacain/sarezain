"""Orquestador del escaneo: descubrimiento → puertos → servicios → evaluación."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Callable

from . import checks, discovery, netinfo, ports, probes, safety, storage, vendors

PHASES = [
    ("discovery", "Buscando dispositivos", 0.0, 0.35),
    ("ports", "Escaneando puertos", 0.35, 0.75),
    ("services", "Analizando servicios", 0.75, 0.95),
    ("evaluate", "Evaluando riesgos", 0.95, 1.0),
]

ProgressFn = Callable[[str, str, float], None]


async def run_scan(network: str | None = None, on_progress: ProgressFn | None = None) -> dict:
    local = netinfo.detect()
    net = safety.validate_network(network or local.network)
    started = datetime.now()
    t0 = time.monotonic()

    def phase_progress(key: str):
        _, label, start, end = next(p for p in PHASES if p[0] == key)

        def report(fraction: float):
            if on_progress:
                on_progress(key, label, start + (end - start) * min(max(fraction, 0), 1))
        report(0)
        return report

    # 1. Descubrimiento
    report = phase_progress("discovery")
    found = await discovery.discover(net, report)
    if local.ip not in found and local.ip in [str(h) for h in net.hosts()]:
        found[local.ip] = {"mac": local.mac, "via": ["local"], "ssdp": None}
    names = await discovery.resolve_names(list(found))

    # 2. Puertos
    report = phase_progress("ports")
    sem = asyncio.Semaphore(400)
    open_ports: dict[str, list[int]] = {}
    done = 0

    async def scan(ip: str):
        nonlocal done
        open_ports[ip] = await ports.scan_host(ip, sem)
        done += 1
        report(done / len(found))

    await asyncio.gather(*(scan(ip) for ip in found))

    # 3. Servicios
    report = phase_progress("services")
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

    # 4. Evaluación
    phase_progress("evaluate")
    previous = storage.latest(str(net))
    known = set()
    if previous:
        for h in previous["hosts"]:
            known.add(h.get("mac") or h["ip"])

    hosts = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        info = found[ip]
        mac = info.get("mac") or (local.mac if ip == local.ip else None)
        host = {
            "ip": ip,
            "mac": mac,
            "vendor": vendors.lookup(mac),
            "hostname": names.get(ip) or (local.hostname if ip == local.ip else None),
            "is_gateway": ip == local.gateway,
            "is_self": ip == local.ip,
            "seen_by": info.get("via", []),
            "upnp": info.get("ssdp"),
            "services": sorted(service_info[ip], key=lambda s: s["port"]),
            "new": bool(previous) and (mac or ip) not in known,
        }
        host["type"] = checks.guess_type(host)
        host["findings"] = checks.evaluate(host)
        host["risk"] = checks.risk_score(host["findings"])
        host["level"] = checks.risk_level(host["risk"])
        hosts.append(host)

    counts = {sev: 0 for sev in checks.SEVERITY_ORDER}
    for h in hosts:
        for fnd in h["findings"]:
            counts[fnd["severity"]] += 1
    risk = max((h["risk"] for h in hosts), default=0)

    scan = {
        "id": started.strftime("%Y%m%d-%H%M%S"),
        "started": started.isoformat(timespec="seconds"),
        "duration": round(time.monotonic() - t0, 1),
        "network": str(net),
        "local": local.to_dict(),
        "hosts": hosts,
        "summary": {
            "risk": risk,
            "level": checks.risk_level(risk),
            "hosts": len(hosts),
            "open_ports": sum(len(h["services"]) for h in hosts),
            "findings": counts,
            "new_hosts": sum(1 for h in hosts if h["new"]),
        },
        "demo": False,
    }
    storage.save(scan)
    if on_progress:
        on_progress("done", "Completado", 1.0)
    return scan
