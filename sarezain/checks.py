"""Reglas de seguridad: convierten lo observado en hallazgos con gravedad.

Cada hallazgo lleva un `id` estable; `remediation.py` lo usa para escribir la
solución adaptada al dispositivo concreto (sistema, fabricante, modelo...).
"""

from __future__ import annotations

import re
from datetime import date

SEVERITY_WEIGHT = {"critica": 45, "alta": 22, "media": 10, "baja": 3, "info": 0}
SEVERITY_ORDER = ["critica", "alta", "media", "baja", "info"]


def finding(fid: str, sev: str, title: str, detail: str, port: int | None = None,
            ref: str | None = None, **extra) -> dict:
    f = {"id": fid, "severity": sev, "title": title, "detail": detail, "port": port, "ref": ref}
    f.update(extra)
    return f


DB_PORTS = {1433: "SQL Server", 1521: "Oracle", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
            27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch", 6379: "Redis", 5984: "CouchDB",
            9042: "Cassandra", 8086: "InfluxDB"}


def cvss_severity(score: float | None, kev: bool = False) -> str:
    if kev or (score or 0) >= 9:
        return "critica"
    if (score or 0) >= 7:
        return "alta"
    if (score or 0) >= 4:
        return "media"
    return "baja"


# ====================================================================== dispositivos

def evaluate(host: dict) -> list[dict]:
    f: list[dict] = []
    services = {s["port"]: s for s in host.get("services", [])}

    def has(port: int) -> bool:
        return port in services

    if has(23):
        f.append(finding("telnet", "alta", "Telnet abierto",
                         "Telnet envía usuario y contraseña en texto plano: cualquiera en la red puede capturarlos.", 23))
    if has(21):
        if services[21].get("anonymous"):
            f.append(finding("ftp_anon", "alta", "FTP con acceso anónimo",
                             "El servidor FTP permite entrar sin usuario ni contraseña (usuario 'anonymous').", 21))
        f.append(finding("ftp_plain", "media", "FTP sin cifrar",
                         "FTP transmite credenciales y archivos sin cifrar.", 21))
    if has(445):
        if services[445].get("smb1"):
            f.append(finding("smb1", "critica", "SMBv1 activo",
                             "El equipo acepta SMBv1, el protocolo explotado por WannaCry y NotPetya (EternalBlue).", 445,
                             "https://learn.microsoft.com/es-es/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"))
        elif not host.get("is_self"):
            f.append(finding("smb_share", "baja", "Compartición de archivos (SMB) visible",
                             "El equipo comparte archivos o impresoras en la red local.", 445))
    if has(3389) and not host.get("is_self"):
        f.append(finding("rdp", "media", "Escritorio remoto (RDP) accesible",
                         "RDP es un objetivo habitual de ataques de fuerza bruta y ransomware.", 3389))
    for vnc in (5900, 5901):
        if has(vnc):
            f.append(finding("vnc", "alta", "VNC accesible",
                             "VNC da control total del escritorio y muchas instalaciones usan contraseñas débiles o ninguna.", vnc))
    if has(5555):
        f.append(finding("adb", "critica", "Depuración Android (ADB) por red",
                         "ADB en red permite instalar apps y ejecutar comandos en el dispositivo sin contraseña.", 5555))
    if has(5985) or has(5986):
        f.append(finding("winrm", "media", "Administración remota de Windows (WinRM) accesible",
                         "WinRM permite ejecutar comandos de forma remota si se conocen credenciales.", 5985 if has(5985) else 5986))
    if has(4444):
        f.append(finding("backdoor_port", "alta", "Puerto típico de puertas traseras (4444)",
                         "El puerto 4444 lo usan por defecto herramientas de control remoto como Metasploit.", 4444))

    for port, name in DB_PORTS.items():
        if not has(port):
            continue
        s = services[port]
        if port == 6379 and s.get("no_auth"):
            f.append(finding("redis_noauth", "critica", "Redis sin contraseña",
                             "Cualquiera en la red puede leer, modificar o borrar los datos de Redis.", port))
        elif port == 9200 and s.get("open_api"):
            f.append(finding("elastic_noauth", "critica", "Elasticsearch sin autenticación",
                             "La API de Elasticsearch responde sin credenciales: los índices son accesibles.", port))
        else:
            f.append(finding("db_exposed", "alta", f"Base de datos {name} accesible en la red",
                             f"El puerto de {name} acepta conexiones de otros equipos de la red.", port, db=name))
    if has(2375) and services[2375].get("open_api"):
        f.append(finding("docker_api", "critica", "API de Docker sin protección",
                         "La API de Docker sin TLS permite crear contenedores con acceso root al equipo.", 2375))

    if has(554):
        f.append(finding("rtsp", "media", "Stream de vídeo RTSP accesible",
                         "Típico de cámaras IP: el vídeo puede verse si el stream no tiene contraseña.", 554))
    if has(1883):
        f.append(finding("mqtt", "media", "MQTT sin cifrar",
                         "Broker MQTT (domótica/IoT) en texto plano: los mensajes pueden leerse o inyectarse.", 1883))
    if has(7547):
        f.append(finding("tr069", "media", "TR-069 accesible",
                         "Protocolo de gestión remota del operador; ha sido explotado por botnets como Mirai.", 7547))
    if host.get("snmp"):
        f.append(finding("snmp_public", "alta", "SNMP con comunidad por defecto 'public'",
                         f"El equipo revela información interna a cualquiera ({host['snmp'][:80]}).", 161))
    if host.get("upnp"):
        f.append(finding("upnp", "baja", "UPnP activo",
                         f"Responde a descubrimiento UPnP ({host['upnp'].get('server') or 'servidor desconocido'}).", None))

    for port, s in services.items():
        if "tls" not in s:
            continue
        if not s.get("tls") and (s.get("login_form") or s.get("basic_auth")):
            f.append(finding("http_login", "media", "Formulario de acceso sin cifrar",
                             f"La página '{s.get('title') or 'sin título'}' pide contraseña por HTTP: viaja en claro.", port))
        if s.get("version") and s.get("product") and not s["product"].startswith("Microsoft-HTTPAPI"):
            f.append(finding("server_version", "baja", "El servidor web revela su versión",
                             f"Cabecera Server: {s['product']} {s['version']}. Facilita buscar vulnerabilidades conocidas.", port))
        cert = s.get("certificate") or {}
        if cert.get("expired"):
            f.append(finding("tls_expired", "media", "Certificado TLS caducado",
                             f"El certificado de '{cert.get('subject')}' caducó el {(cert.get('expires') or '')[:10]}.", port))
        elif cert.get("self_signed"):
            f.append(finding("tls_selfsigned", "baja", "Certificado TLS autofirmado",
                             "El navegador no puede verificar la identidad del servidor (habitual en routers y NAS).", port))
        if s.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            f.append(finding("tls_old", "media", f"Protocolo obsoleto {s['tls_version']}",
                             "El servidor negocia una versión de TLS considerada insegura.", port))
        cipher = s.get("cipher") or ""
        if cipher and s.get("tls_version") != "TLSv1.3" and not cipher.startswith(("ECDHE", "DHE")):
            f.append(finding("tls_nofs", "baja", "TLS sin secreto perfecto hacia delante",
                             f"El servidor usa {cipher} (intercambio de claves RSA). Si su clave privada se filtra, "
                             "el tráfico grabado en el pasado podría descifrarse.", port))

    # Vulnerabilidades conocidas por versión
    for port, s in services.items():
        info = s.get("cve")
        if not info or not info.get("cves"):
            continue
        top = info["cves"][0]
        worst = max((c["cvss"] or 0) for c in info["cves"])
        kev = any(c["kev"] for c in info["cves"])
        n = info["total"]
        detail = (f"{s.get('product')} {s.get('version')} tiene {n} vulnerabilidad{'es' if n != 1 else ''} "
                  f"conocida{'s' if n != 1 else ''} (CVSS máx. {worst:.1f})"
                  + (", alguna explotada activamente según la CISA." if kev else "."))
        f.append(finding("cve", cvss_severity(worst, kev), f"{s.get('product')} {s.get('version')} vulnerable",
                         detail, port, f"https://nvd.nist.gov/vuln/detail/{top['id']}",
                         cves=info["cves"][:10], product=s.get("product"), version=s.get("version")))

    if host.get("new"):
        f.append(finding("new_device", "info", "Dispositivo nuevo",
                         "No estaba en el escaneo anterior. Comprueba que lo reconoces."))

    f.sort(key=lambda x: SEVERITY_ORDER.index(x["severity"]))
    return f


# ====================================================================== red

def evaluate_network(net: dict, hosts: list[dict]) -> list[dict]:
    f: list[dict] = []
    wifi = net.get("wifi")
    if wifi:
        auth = (wifi.get("auth") or "").lower()
        cipher = (wifi.get("cipher") or "").lower()
        if "abierta" in auth or auth == "open":
            f.append(finding("wifi_open", "critica", "Wi-Fi sin contraseña",
                             f"La red '{wifi['ssid']}' está abierta: cualquiera cercano puede conectarse y ver tu tráfico local."))
        elif "wep" in auth or "wep" in cipher:
            f.append(finding("wifi_wep", "critica", "Wi-Fi con cifrado WEP",
                             "WEP se rompe en minutos con herramientas gratuitas."))
        elif "tkip" in cipher or auth.startswith("wpa-") or auth == "wpa-personal":
            f.append(finding("wifi_tkip", "alta", "Wi-Fi con WPA/TKIP",
                             f"La red usa {wifi.get('auth')} / {wifi.get('cipher')}, un cifrado antiguo con debilidades conocidas."))
        elif "wpa3" not in auth:
            f.append(finding("wifi_wpa2", "baja", "Wi-Fi con WPA2 (sin WPA3)",
                             f"La red usa {wifi.get('auth')}. Es correcto, pero WPA3 protege mejor frente a ataques de diccionario."))
        if wifi.get("isp"):
            f.append(finding("wifi_default_ssid", "media", "Nombre de Wi-Fi de fábrica",
                             f"'{wifi['ssid']}' es el nombre que pone {wifi['isp']} por defecto. Suele indicar que la "
                             "contraseña también es la de fábrica (la de la pegatina), y revela el modelo de router."))
        if wifi.get("twins"):
            t = wifi["twins"][0]
            f.append(finding("evil_twin", "alta", "Posible red Wi-Fi suplantada",
                             f"Hay otra red cercana con el mismo nombre '{wifi['ssid']}' pero con seguridad distinta "
                             f"({t['auth']}). Puede ser un 'gemelo malvado' para robar contraseñas.",
                             bssids=t.get("bssids")))

    for a in net.get("arp_anomalies", []):
        f.append(finding("arp_spoof", "alta" if a["involves_gateway"] else "media",
                         "Posible suplantación ARP" if a["involves_gateway"] else "MAC repetida en varias IP",
                         f"La MAC {a['mac']} responde por {', '.join(a['ips'])}."
                         + (" Incluye al router: alguien podría estar interceptando el tráfico." if a["involves_gateway"] else ""),
                         mac=a["mac"], ips=a["ips"]))

    upnp = net.get("upnp_igd")
    if upnp:
        f.append(finding("router_upnp", "media", "El router permite abrir puertos por UPnP",
                         "Cualquier programa de la red (incluido malware) puede abrir puertos hacia Internet sin pedir permiso."))
        for m in upnp.get("mappings", []):
            risky = m["internal_port"] in (22, 23, 445, 3389, 5900, 3306, 1433, 5432, 6379, 21, 554)
            f.append(finding("upnp_forward", "alta" if risky else "media",
                             f"Puerto {m['external_port']}/{m['protocol']} abierto a Internet",
                             f"El router reenvía el puerto {m['external_port']} desde Internet a {m['internal_ip']}:{m['internal_port']}"
                             f" ({m.get('description') or 'sin descripción'}).", m["external_port"], mapping=m))

    dns = net.get("dns") or []
    if dns and not any("anti-malware" in d["provider"] or "AdGuard" in d["provider"] for d in dns):
        f.append(finding("dns_plain", "info", "DNS sin filtrado de amenazas",
                         "Usas " + ", ".join(f"{d['server']} ({d['provider']})" for d in dns) +
                         ". Un DNS con filtrado bloquea dominios de malware y phishing para toda la red."))

    if (net.get("ipv6") or {}).get("global"):
        f.append(finding("ipv6_global", "info", "IPv6 público activo",
                         "Los equipos tienen dirección IPv6 pública. Su protección depende del firewall IPv6 del router."))

    f.sort(key=lambda x: SEVERITY_ORDER.index(x["severity"]))
    return f


# ====================================================================== este equipo

def evaluate_local(loc: dict | None) -> list[dict]:
    if not loc:
        return []
    f: list[dict] = []
    os_info = loc.get("os") or {}
    build = os_info.get("build") or 0
    caption = os_info.get("caption") or "Windows"
    if build and build < 22000 and date.today() >= date(2025, 10, 14):
        f.append(finding("win10_eol", "alta", "Windows 10 sin soporte",
                         f"{caption} dejó de recibir actualizaciones de seguridad el 14/10/2025 (salvo ESU)."))
    for p in loc.get("firewall", []):
        if not p.get("enabled"):
            f.append(finding("fw_off", "alta", f"Firewall desactivado (perfil {p['name']})",
                             f"El firewall de Windows está apagado en el perfil {p['name']}.", profile=p["name"]))
    d = loc.get("defender")
    others = [a for a in loc.get("antivirus", []) if "defender" not in (a.get("name") or "").lower()]
    if d and not d.get("realtime") and not others:
        f.append(finding("av_off", "critica", "Protección antivirus en tiempo real desactivada",
                         "Microsoft Defender no está vigilando los archivos en tiempo real y no hay otro antivirus activo."))
    elif d and d.get("sig_age", 0) > 7:
        f.append(finding("av_old", "media", "Firmas del antivirus desactualizadas",
                         f"Las firmas de Defender tienen {d['sig_age']} días."))
    if d and d.get("av") and not d.get("tamper"):
        f.append(finding("tamper_off", "baja", "Protección contra alteraciones desactivada",
                         "Sin ella, el malware puede desactivar Defender."))
    smb = loc.get("smb") or {}
    if smb.get("smb1"):
        f.append(finding("smb1", "critica", "SMBv1 activo en este equipo",
                         "Este equipo acepta SMBv1 (EternalBlue/WannaCry).", 445))
    elif smb and not smb.get("signing"):
        f.append(finding("smb_signing", "baja", "Firma SMB no obligatoria",
                         "Sin firma obligatoria, otro equipo de la red podría hacer ataques de retransmisión (NTLM relay)."))
    if loc.get("rdp_enabled"):
        f.append(finding("rdp_local", "media", "Escritorio remoto activado en este equipo",
                         "El equipo acepta conexiones de Escritorio remoto.", 3389))
    uac = loc.get("uac") or {}
    if uac and not uac.get("enabled"):
        f.append(finding("uac_off", "alta", "Control de cuentas (UAC) desactivado",
                         "Cualquier programa se ejecuta con permisos de administrador sin avisar."))
    elif uac.get("prompt") == 0:
        f.append(finding("uac_silent", "media", "UAC eleva sin preguntar",
                         "El UAC está configurado para no pedir confirmación a los administradores."))
    if loc.get("last_update"):
        try:
            days = (date.today() - date.fromisoformat(loc["last_update"])).days
            if days > 45:
                f.append(finding("updates_old", "alta" if days > 90 else "media", "Actualizaciones de Windows atrasadas",
                                 f"La última actualización instalada ({loc.get('last_update_id')}) es de hace {days} días.", days=days))
        except ValueError:
            pass
    if loc.get("guest_enabled"):
        f.append(finding("guest_on", "media", "Cuenta de invitado activada",
                         "La cuenta Invitado permite entrar al equipo sin contraseña."))
    if loc.get("bitlocker") in (2,):
        f.append(finding("bitlocker_off", "media", "Disco sin cifrar (BitLocker desactivado)",
                         "Si te roban el portátil, pueden leer todos los archivos sacando el disco."))
    risky_listen = [x for x in loc.get("listening", []) if x["port"] < 49152 and x["port"] not in (135, 445, 5040, 5357)]
    if risky_listen:
        f.append(finding("listening", "baja", "Servicios escuchando en la red",
                         "Este equipo acepta conexiones de la red local en: " +
                         ", ".join(f"{x['port']} ({x.get('process') or '?'})" for x in risky_listen) + ".",
                         listening=risky_listen))
    if loc.get("network_category") == "Private":
        f.append(finding("net_private", "info", "Red marcada como privada",
                         "En redes privadas Windows es visible y comparte recursos. Está bien en casa; en redes públicas, márcala como pública."))
    f.sort(key=lambda x: SEVERITY_ORDER.index(x["severity"]))
    return f


# ====================================================================== puntuación y tipo

def risk_score(findings: list[dict]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[x["severity"]] for x in findings))


def risk_level(score: int) -> str:
    if score >= 45:
        return "critica"
    if score >= 22:
        return "alta"
    if score >= 10:
        return "media"
    if score > 0:
        return "baja"
    return "ok"


def guess_type(host: dict) -> str:
    ports = {s["port"] for s in host.get("services", [])}
    vendor = (host.get("vendor") or "").lower()
    name = " ".join(filter(None, [host.get("hostname"), host.get("model"), (host.get("upnp_info") or {}).get("modelName"),
                                  (host.get("upnp_info") or {}).get("friendlyName"), (host.get("upnp") or {}).get("server")])).lower()
    mdns = " ".join(host.get("mdns_services") or []).lower()
    text = " ".join(str(s.get("title") or "") + " " + str(s.get("product") or "") for s in host.get("services", [])).lower()

    if host.get("is_gateway"):
        return "router"
    if host.get("is_self"):
        return "pc"
    if ports & {9100, 515, 631} or "impres" in mdns or any(k in vendor for k in ("epson", "brother", "canon", "lexmark", "kyocera", "xerox")):
        return "impresora"
    if 554 in ports or 37777 in ports or any(k in vendor for k in ("hikvision", "dahua", "axis", "reolink", "ezviz", "amcrest")):
        return "camara"
    tv_model_name = bool(re.match(r"^\d{2}[a-z]{1,4}\d{2,4}", (host.get("hostname") or "").lower()))  # 65FZ950, 55UN7300...
    if tv_model_name or (55000 in ports and "panasonic" in name + vendor) \
            or any(k in name for k in ("viera", "bravia", "tv", "dlna", "chromecast", "fire tv", "roku", "android tv")) \
            or any(k in mdns for k in ("chromecast", "fire tv", "android tv", "airplay")) and "apple" not in vendor \
            or ports & {8008, 8009} or any(k in vendor for k in ("roku", "sonos", "lg electronics", "tcl", "hisense", "vizio", "panasonic")):
        return "tv"
    if 62078 in ports or any(k in name for k in ("iphone", "ipad", "android", "galaxy", "pixel", "redmi", "xiaomi")):
        return "movil"
    if "mac privada" in vendor:
        return "movil"
    if ports & {1883} or "spotify" in mdns or "homekit" in mdns or "matter" in mdns or any(
            k in vendor for k in ("espressif", "tuya", "shelly", "sonoff", "philips lighting", "signify", "amazon")):
        return "iot"
    if any(k in text + name for k in ("synology", "qnap", "nas")) or any(k in vendor for k in ("synology", "qnap", "western digital")):
        return "nas"
    if ports & {3389, 135, 139} or "microsoft" in vendor:
        return "pc"
    if 22 in ports or "raspberry" in vendor:
        return "servidor"
    if any(k in vendor for k in ("tp-link", "netgear", "asus", "ubiquiti", "mikrotik", "zyxel", "huawei", "sagemcom", "arcadyan", "askey", "zte", "mitrastar")):
        return "red"
    if any(k in vendor for k in ("apple", "samsung", "xiaomi", "oneplus", "oppo", "motorola")):
        return "movil"
    return "desconocido"
