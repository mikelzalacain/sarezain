"""Reglas de seguridad: convierten lo observado en hallazgos con gravedad y solución."""

from __future__ import annotations

SEVERITY_WEIGHT = {"critica": 45, "alta": 22, "media": 10, "baja": 3, "info": 0}
SEVERITY_ORDER = ["critica", "alta", "media", "baja", "info"]


def finding(sev: str, title: str, detail: str, fix: str, port: int | None = None, ref: str | None = None) -> dict:
    return {"severity": sev, "title": title, "detail": detail, "fix": fix, "port": port, "ref": ref}


DB_PORTS = {1433: "SQL Server", 1521: "Oracle", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
            27017: "MongoDB", 11211: "Memcached", 9200: "Elasticsearch", 6379: "Redis"}


def evaluate(host: dict) -> list[dict]:
    f: list[dict] = []
    services = {s["port"]: s for s in host.get("services", [])}

    def has(port: int) -> bool:
        return port in services

    # --- accesos remotos y protocolos sin cifrar
    if has(23):
        f.append(finding("alta", "Telnet abierto",
                         "Telnet envía usuario y contraseña en texto plano: cualquiera en la red puede capturarlos.",
                         "Desactiva Telnet y usa SSH. En routers y cámaras suele estar en 'Administración' o 'Servicios'.", 23))
    if has(21):
        ftp = services[21]
        if ftp.get("anonymous"):
            f.append(finding("alta", "FTP con acceso anónimo",
                             "El servidor FTP permite entrar sin usuario ni contraseña (usuario 'anonymous').",
                             "Desactiva el acceso anónimo o restringe la carpeta a solo lectura con contenido público.", 21))
        f.append(finding("media", "FTP sin cifrar",
                         "FTP transmite credenciales y archivos sin cifrar.",
                         "Usa SFTP (sobre SSH) o FTPS en lugar de FTP.", 21))
    if has(445):
        if services[445].get("smb1"):
            f.append(finding("critica", "SMBv1 activo",
                             "El equipo acepta SMBv1, el protocolo explotado por WannaCry y NotPetya (EternalBlue).",
                             "Desactiva SMBv1: en Windows, 'Activar o desactivar características' → quitar 'Compatibilidad con SMB 1.0/CIFS'.",
                             445, "https://learn.microsoft.com/es-es/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"))
        else:
            f.append(finding("baja", "Compartición de archivos (SMB) visible",
                             "El equipo comparte archivos o impresoras en la red local.",
                             "Comprueba qué carpetas compartes y que ninguna permita acceso de invitado.", 445))
    if has(3389):
        f.append(finding("media", "Escritorio remoto (RDP) accesible",
                         "RDP es un objetivo habitual de ataques de fuerza bruta y ransomware.",
                         "Desactívalo si no lo usas, exige NLA y no lo publiques nunca a Internet (usa una VPN).", 3389))
    for vnc in (5900, 5901):
        if has(vnc):
            f.append(finding("alta", "VNC accesible",
                             "VNC da control total del escritorio y muchas versiones usan contraseñas débiles o ninguna.",
                             "Desactívalo o limítalo a localhost y accede mediante un túnel SSH o VPN.", vnc))
    if has(5555):
        f.append(finding("critica", "Depuración Android (ADB) por red",
                         "ADB en red permite instalar apps y ejecutar comandos en el dispositivo sin contraseña.",
                         "Desactiva 'Depuración inalámbrica' / 'ADB por red' en las opciones de desarrollador.", 5555))

    # --- bases de datos y APIs
    for port, name in DB_PORTS.items():
        if not has(port):
            continue
        s = services[port]
        if port == 6379 and s.get("no_auth"):
            f.append(finding("critica", "Redis sin contraseña",
                             "Cualquiera en la red puede leer, modificar o borrar los datos de Redis.",
                             "Configura 'requirepass' o ACLs y enlaza Redis solo a 127.0.0.1.", port))
        elif port == 9200 and s.get("open_api"):
            f.append(finding("critica", "Elasticsearch sin autenticación",
                             "La API de Elasticsearch responde sin credenciales: los índices son accesibles.",
                             "Activa la seguridad de Elasticsearch (xpack.security) y limita el acceso por red.", port))
        else:
            f.append(finding("alta", f"Base de datos {name} accesible en la red",
                             f"El puerto de {name} acepta conexiones de otros equipos de la red.",
                             "Si solo la usa este equipo, enlázala a 127.0.0.1; si no, filtra el acceso con el firewall.", port))
    if has(2375) and services[2375].get("open_api"):
        f.append(finding("critica", "API de Docker sin protección",
                         "La API de Docker sin TLS permite crear contenedores con acceso root al equipo.",
                         "Desactiva el socket TCP 2375 o protégelo con TLS mutuo (puerto 2376).", 2375))

    # --- IoT / router
    if has(554):
        f.append(finding("media", "Stream de vídeo RTSP accesible",
                         "Típico de cámaras IP: el vídeo puede verse si el stream no tiene contraseña.",
                         "Cambia la contraseña por defecto de la cámara y actualiza su firmware.", 554))
    if has(1883):
        f.append(finding("media", "MQTT sin cifrar",
                         "Broker MQTT (domótica/IoT) en texto plano: los mensajes pueden leerse o inyectarse.",
                         "Activa autenticación y usa MQTT sobre TLS (puerto 8883).", 1883))
    if has(7547):
        f.append(finding("media", "TR-069 accesible",
                         "Protocolo de gestión remota del operador; ha sido explotado por botnets como Mirai.",
                         "Si el router es tuyo y no lo gestiona tu operador, desactiva TR-069/CWMP.", 7547))
    if host.get("upnp"):
        f.append(finding("baja", "UPnP activo",
                         f"Responde a descubrimiento UPnP ({host['upnp'].get('server') or 'servidor desconocido'}). "
                         "UPnP permite que cualquier app abra puertos del router hacia Internet.",
                         "Desactiva UPnP en el router si no lo necesitas (consolas y algunas apps lo usan)."))

    # --- web
    for port, s in services.items():
        if "tls" not in s:
            continue
        tls = s.get("tls")
        if not tls and (s.get("login_form") or s.get("basic_auth")):
            f.append(finding("media", "Formulario de acceso sin cifrar",
                             f"La página '{s.get('title') or 'sin título'}' pide contraseña por HTTP: viaja en claro.",
                             "Activa HTTPS en el panel de administración y desactiva el acceso por HTTP.", port))
        if s.get("version") and s.get("product"):
            f.append(finding("baja", "El servidor web revela su versión",
                             f"Cabecera Server: {s['product']} {s['version']}. Facilita buscar vulnerabilidades conocidas.",
                             "Oculta la versión (p. ej. 'ServerTokens Prod' en Apache, 'server_tokens off' en nginx).", port))
        cert = s.get("certificate") or {}
        if cert.get("expired"):
            f.append(finding("media", "Certificado TLS caducado",
                             f"El certificado de '{cert.get('subject')}' caducó el {cert.get('expires', '')[:10]}.",
                             "Renueva el certificado.", port))
        elif cert.get("self_signed"):
            f.append(finding("baja", "Certificado TLS autofirmado",
                             "El navegador no puede verificar la identidad del servidor (habitual en routers y NAS).",
                             "Si es un servicio que usas a menudo, instala un certificado de una CA o de tu CA interna.", port))
        if s.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            f.append(finding("media", f"Protocolo obsoleto {s['tls_version']}",
                             "El servidor negocia una versión de TLS considerada insegura.",
                             "Configura el servidor para aceptar solo TLS 1.2 y 1.3.", port))
        cipher = s.get("cipher") or ""
        if cipher and s.get("tls_version") != "TLSv1.3" and not cipher.startswith(("ECDHE", "DHE")):
            f.append(finding("baja", "TLS sin secreto perfecto hacia delante",
                             f"El servidor usa {cipher} (intercambio de claves RSA). Si su clave privada se filtra, "
                             "el tráfico grabado en el pasado podría descifrarse.",
                             "Prioriza suites ECDHE y activa TLS 1.3 si el equipo lo permite (actualiza el firmware).", port))

    if host.get("new"):
        f.append(finding("info", "Dispositivo nuevo",
                         "No estaba en el escaneo anterior. Comprueba que lo reconoces.",
                         "Si no sabes qué es, revisa el router (lista de clientes) y cambia la contraseña del Wi-Fi."))

    f.sort(key=lambda x: SEVERITY_ORDER.index(x["severity"]))
    return f


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
    name = (host.get("hostname") or "").lower()
    text = " ".join(str(s.get("title") or "") + " " + str(s.get("product") or "")
                    for s in host.get("services", [])).lower()

    if host.get("is_gateway"):
        return "router"
    if host.get("is_self"):
        return "pc"
    if ports & {9100, 515, 631} or any(k in vendor for k in ("epson", "brother", "canon", "lexmark", "kyocera", "xerox")):
        return "impresora"
    if 554 in ports or any(k in vendor for k in ("hikvision", "dahua", "axis", "reolink", "ezviz", "amcrest")):
        return "camara"
    if ports & {8008, 8009} or any(k in vendor + name for k in ("roku", "chromecast", "sonos", "lg electronics", "tcl", "hisense", "vizio")):
        return "tv"
    if 62078 in ports or any(k in name for k in ("iphone", "ipad", "android", "galaxy", "pixel", "redmi", "xiaomi")):
        return "movil"
    if "mac privada" in vendor:
        return "movil"
    if ports & {1883} or any(k in vendor for k in ("espressif", "tuya", "shelly", "sonoff", "tp-link smart", "philips lighting", "signify")):
        return "iot"
    if any(k in text for k in ("synology", "qnap", "nas")) or any(k in vendor for k in ("synology", "qnap", "western digital")):
        return "nas"
    if ports & {3389, 135, 139} or "microsoft" in vendor:
        return "pc"
    if 22 in ports or "raspberry" in vendor:
        return "servidor"
    if ports & {80, 443} and any(k in vendor for k in ("tp-link", "netgear", "asus", "ubiquiti", "mikrotik", "zyxel", "huawei", "sagemcom", "arcadyan", "askey")):
        return "red"
    if any(k in vendor for k in ("apple", "samsung", "xiaomi", "oneplus", "oppo", "motorola", "huawei")):
        return "movil"
    return "desconocido"
