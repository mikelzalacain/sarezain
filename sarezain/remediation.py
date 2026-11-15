"""Soluciones personalizadas: adapta cada hallazgo al dispositivo concreto.

Para cada hallazgo genera:
  - `fix`:      resumen de una línea
  - `steps`:    pasos concretos para ESE equipo (según sistema, fabricante, modelo y operador)
  - `commands`: comandos listos para copiar cuando aplican (PowerShell, bash, smb.conf...)
  - `context`:  por qué se da esta solución ("Detectado como TV Panasonic TX-65FZ950E")
"""

from __future__ import annotations


# ---------------------------------------------------------------- perfil del dispositivo

def profile(host: dict | None) -> str:
    if host is None:
        return "network"
    if host.get("is_self"):
        return "self_windows" if "windows" in (host.get("os") or "windows").lower() else "self_other"
    t, os_ = host.get("type"), (host.get("os") or "").lower()
    if t == "router":
        return "router"
    if "synology" in os_:
        return "nas_synology"
    if "qnap" in os_:
        return "nas_qnap"
    if t == "nas":
        return "nas"
    if t in ("tv", "impresora", "camara", "iot", "movil", "red"):
        if t == "movil":
            return "mobile_ios" if "ios" in os_ else ("mobile_android" if "android" in os_ else "mobile")
        return {"tv": "tv", "impresora": "printer", "camara": "camera", "iot": "iot", "red": "network_device"}[t]
    if "windows" in os_:
        return "windows"
    if "macos" in os_:
        return "macos"
    if "linux" in os_ or "unix" in os_ or t == "servidor":
        return "linux"
    return "unknown"


def describe(host: dict | None, ctx: dict) -> str | None:
    if host is None:
        return None
    upnp = host.get("upnp_info") or {}
    model = " ".join(filter(None, [upnp.get("manufacturer"), upnp.get("modelNumber") or upnp.get("modelName")])) or host.get("model")
    parts = []
    if host.get("is_self"):
        parts.append(f"este equipo ({host.get('os') or 'Windows'})")
    elif host.get("is_gateway"):
        parts.append("tu router" + (f" de {ctx['isp']}" if ctx.get("isp") else ""))
    else:
        label = {"tv": "TV / streaming", "impresora": "impresora", "camara": "cámara IP", "iot": "dispositivo IoT",
                 "movil": "móvil o tablet", "nas": "NAS", "pc": "ordenador", "servidor": "servidor", "red": "equipo de red"}.get(host.get("type"), "dispositivo")
        parts.append(label)
        if model:
            parts.append(model)
        elif host.get("vendor"):
            parts.append(f"de {host['vendor']}")
        if host.get("os") and host.get("type") in ("pc", "servidor", "desconocido"):
            parts.append(f"con {host['os']}")
    return "Detectado como " + " ".join(parts)


def _router_url(ctx: dict) -> str:
    return f"http://{ctx.get('gateway') or '192.168.1.1'}"


def _router_steps(ctx: dict, what: str) -> list[str]:
    steps = [f"Entra en el panel del router: {_router_url(ctx)} (la contraseña de administración suele venir en la pegatina del router)."]
    steps.append(what)
    if ctx.get("isp"):
        steps.append(f"Es un router de {ctx['isp']}: si la opción no aparece o está bloqueada, pídelo al soporte técnico de {ctx['isp']} "
                     "o valora usar un router propio detrás del suyo.")
    return steps


def _firmware_steps(host: dict, kind: str) -> list[str]:
    upnp = host.get("upnp_info") or {}
    model = upnp.get("modelNumber") or upnp.get("modelName") or host.get("model")
    vendor = upnp.get("manufacturer") or host.get("vendor") or "el fabricante"
    s = []
    if kind == "tv":
        s.append("En el mando: Menú → Ayuda/Soporte → Actualización de software, y actualiza si hay versión nueva.")
    elif kind == "printer":
        s.append(f"Abre el panel web de la impresora (http://{host['ip']}) y busca 'Actualizar firmware'.")
    else:
        s.append("Actualiza el firmware desde su app o panel web.")
    if model:
        s.append(f"Comprueba en la web de soporte de {vendor} si hay firmware nuevo para el modelo {model}.")
    return s


def _isolate_step(ctx: dict) -> str:
    return ("Si no puedes corregirlo, conéctalo a la red Wi-Fi de invitados del router (si la tiene) para aislarlo de tus "
            "ordenadores y móviles.")


# ---------------------------------------------------------------- soluciones por hallazgo

def _smb1(host, ctx, p):
    if p == "self_windows":
        return ("Desactiva SMBv1 en este equipo.",
                ["Abre PowerShell como administrador y ejecuta los comandos.", "Reinicia el equipo."],
                [{"label": "PowerShell (administrador)", "code":
                  "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                  "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"}])
    if p == "windows":
        return ("Desactiva SMBv1 en ese PC.",
                ["En ese equipo: Inicio → 'Activar o desactivar las características de Windows'.",
                 "Desmarca 'Compatibilidad con el protocolo para compartir archivos SMB 1.0/CIFS' y reinicia."],
                [{"label": "O en PowerShell (administrador) en ese PC", "code":
                  "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"}])
    if p == "linux":
        return ("Fuerza SMB2 como mínimo en Samba.",
                ["Edita /etc/samba/smb.conf y añade la línea en la sección [global].", "Reinicia Samba."],
                [{"label": "/etc/samba/smb.conf → [global]", "code": "server min protocol = SMB2_10"},
                 {"label": "bash", "code": "sudo systemctl restart smbd"}])
    if p == "nas_synology":
        return ("Sube el protocolo SMB mínimo en DSM.",
                ["Panel de control → Servicios de archivos → SMB → Configuración avanzada.",
                 "En 'Protocolo SMB mínimo' elige SMB2 (o SMB2 y Large MTU). Guarda."], [])
    if p == "nas_qnap":
        return ("Sube la versión mínima de SMB en QTS.",
                ["Panel de control → Red y servicios de archivos → Win/Mac/NFS → Microsoft Networking → Opciones avanzadas.",
                 "Versión SMB mínima: SMB 2.1 o superior. Aplica."], [])
    if p == "tv":
        return ("Tu TV usa SMBv1 para compartir archivos: no se puede reconfigurar desde fuera.",
                ["En la TV, busca en Menú → Red las opciones de 'compartir', 'servidor de medios' o 'carpetas de red' y desactívalas si no las usas.",
                 *_firmware_steps(host, "tv"),
                 _isolate_step(ctx)], [])
    if p == "printer":
        return ("Desactiva SMB/compartición en la impresora.",
                [f"Panel web http://{host['ip']} → Red → Protocolos: desactiva 'SMB', 'Compartir en red Windows' o 'Escanear a carpeta' con SMB1.",
                 *_firmware_steps(host, "printer")], [])
    return ("Desactiva SMBv1 en ese dispositivo o actualízalo.",
            ["Si es un ordenador: desactiva 'SMB 1.0/CIFS' en las características del sistema.",
             "Si es un aparato (TV, NAS, decodificador): busca la opción de compartir archivos o actualiza el firmware.",
             _isolate_step(ctx)], [])


def _rdp(host, ctx, p):
    if p in ("self_windows",):
        return ("Desactiva el Escritorio remoto si no lo usas.",
                ["Configuración → Sistema → Escritorio remoto → Desactivado.",
                 "Si lo necesitas, déjalo activo solo con NLA y accede por VPN, nunca abriendo el puerto 3389 en el router."],
                [{"label": "PowerShell (administrador)", "code":
                  "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1\n"
                  "Disable-NetFirewallRule -DisplayGroup 'Escritorio remoto'"}])
    name = host.get("hostname") or host.get("vendor") or host["ip"]
    return (f"Desactiva el Escritorio remoto en {name} si no se usa.",
            [f"En ese PC ({host['ip']}): Configuración → Sistema → Escritorio remoto → Desactivado.",
             "Si se usa: exige 'Autenticación a nivel de red (NLA)', usa contraseñas largas y limita el acceso a tu IP desde el firewall.",
             "Nunca redirijas el puerto 3389 desde el router a Internet: usa una VPN."],
            [{"label": "PowerShell (administrador) en ese PC", "code":
              "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1"}])


def _telnet(host, ctx, p):
    if p == "router":
        return ("Desactiva Telnet en el router.", _router_steps(ctx, "Busca en Administración / Gestión remota / Servicios la opción Telnet y desactívala."), [])
    if p == "linux":
        return ("Desinstala el servidor Telnet y usa SSH.", ["Elimina el servicio y asegúrate de que SSH está activo."],
                [{"label": "bash (Debian/Ubuntu/Raspberry Pi OS)", "code": "sudo systemctl disable --now inetd telnetd 2>/dev/null\nsudo apt purge -y telnetd inetutils-telnetd\nsudo systemctl enable --now ssh"}])
    if p in ("camera", "iot", "network_device"):
        return ("Desactiva Telnet o actualiza el firmware.",
                [f"Panel web http://{host['ip']} → Sistema/Red/Servicios: desactiva Telnet.",
                 "Cambia la contraseña por defecto (Telnet abierto en IoT es la vía de entrada de botnets como Mirai).",
                 *_firmware_steps(host, "other"), _isolate_step(ctx)], [])
    return ("Desactiva Telnet y usa SSH.", ["Desactiva el servicio Telnet en ese equipo.", _isolate_step(ctx)], [])


def _upnp(host, ctx, p):
    if p == "router":
        return ("Desactiva UPnP en el router si no lo necesitas.",
                _router_steps(ctx, "Busca la opción UPnP (suele estar en Red, NAT o Avanzado) y desactívala. "
                                   "Consolas y algunas apps de videollamada pueden necesitarlo: si algo deja de funcionar, abre solo ese puerto manualmente."), [])
    if p == "tv":
        return ("UPnP/DLNA en la TV sirve para compartir contenido; el riesgo es bajo.",
                ["Si no usas 'servidor de medios' o 'compartir contenido', desactívalo en Menú → Red.",
                 "Lo importante es que el ROUTER no tenga UPnP abierto a Internet (lo revisa la pestaña Red)."], [])
    return ("Desactiva UPnP en el dispositivo si no lo usas.", ["Revisa su panel o app y desactiva UPnP/DLNA."], [])


def _db(host, ctx, p, f):
    name = f.get("db", "la base de datos")
    if p in ("self_windows", "windows"):
        return (f"Limita {name} a este equipo o filtra el puerto.",
                [f"Si solo la usa este PC, configúrala para escuchar en 127.0.0.1.",
                 "Si otros equipos la necesitan, crea una regla de firewall solo para sus IPs."],
                [{"label": "PowerShell (administrador): bloquear el puerto desde la red", "code":
                  f"New-NetFirewallRule -DisplayName 'Bloquear {name}' -Direction Inbound -Protocol TCP -LocalPort {f['port']} -Action Block"}])
    return (f"Enlaza {name} a 127.0.0.1 o filtra el puerto.",
            ["En la configuración del servicio, cambia la dirección de escucha a 127.0.0.1 (bind-address / listen_addresses).",
             "Si otros equipos deben conectarse, permite solo sus IP en el firewall."],
            [{"label": "bash (ufw)", "code": f"sudo ufw deny {f['port']}/tcp\n# o permitir solo un equipo:\n# sudo ufw allow from 192.168.1.50 to any port {f['port']}"}])


def _tls_selfsigned(host, ctx, p):
    if p == "router":
        return ("Es normal en routers domésticos; el riesgo es bajo.",
                ["Accede al panel solo desde tu red y comprueba que el navegador muestra siempre el mismo certificado.",
                 "Si el panel permite subir un certificado propio, puedes usar uno de tu CA interna."], [])
    return ("Usa un certificado de confianza si accedes a menudo a este servicio.",
            ["Puedes crear una CA local (por ejemplo con mkcert) e instalar su raíz en tus equipos."],
            [{"label": "mkcert", "code": f"mkcert -install\nmkcert {host['ip']}"}])


def _tls_nofs(host, ctx, p):
    if p == "router":
        return ("Actualiza el firmware del router; la configuración TLS no suele ser editable.",
                _router_steps(ctx, "Revisa si hay actualización de firmware (Sistema / Mantenimiento)."), [])
    return ("Prioriza suites ECDHE y activa TLS 1.3.", ["En nginx/Apache, usa la configuración 'intermediate' de Mozilla."],
            [{"label": "nginx", "code": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;"}])


def _server_version(host, ctx, p):
    prod = next((s.get("product") for s in host.get("services", []) if s["port"] == host.get("_port")), None) or ""
    cmds = []
    if "apache" in prod.lower():
        cmds = [{"label": "Apache (apache2.conf / httpd.conf)", "code": "ServerTokens Prod\nServerSignature Off"}]
    elif "nginx" in prod.lower():
        cmds = [{"label": "nginx (http {})", "code": "server_tokens off;"}]
    elif "iis" in prod.lower():
        cmds = [{"label": "IIS (web.config)", "code": '<security><requestFiltering removeServerHeader="true" /></security>'}]
    if p in ("router", "tv", "camera", "printer", "iot", "network_device"):
        return ("No es configurable en este tipo de equipo; mantenlo actualizado.", _firmware_steps(host, "other"), [])
    return ("Oculta la versión en la cabecera Server.", ["Añade la directiva correspondiente y recarga el servidor."], cmds)


def _cve(host, ctx, p, f):
    prod, ver = f.get("product"), f.get("version")
    if p in ("router", "tv", "camera", "printer", "iot", "network_device", "nas_synology", "nas_qnap", "nas"):
        steps = (_router_steps(ctx, "Busca 'Actualizar firmware' en Sistema/Mantenimiento.") if p == "router"
                 else _firmware_steps(host, "tv" if p == "tv" else "other"))
        return (f"{prod} {ver} viene integrado en el firmware: actualiza el dispositivo.", steps, [])
    cmds = []
    if p == "linux":
        pkg = {"openssh": "openssh-server", "apache": "apache2", "nginx": "nginx", "vsftpd": "vsftpd",
               "proftpd": "proftpd-basic", "mysql": "mysql-server", "mariadb": "mariadb-server", "lighttpd": "lighttpd"}.get((prod or "").lower())
        if pkg:
            cmds = [{"label": "bash (Debian/Ubuntu/Raspberry Pi OS)", "code": f"sudo apt update && sudo apt install --only-upgrade {pkg}"}]
    return (f"Actualiza {prod} a la última versión.",
            [f"La versión {ver} tiene vulnerabilidades públicas; empieza por las marcadas como explotadas activamente.",
             "Tras actualizar, vuelve a escanear para confirmar."], cmds)


def _generic(text_fix: str, steps: list[str] | None = None, cmds: list[dict] | None = None):
    return text_fix, steps or [], cmds or []


def _network(fid, f, ctx):
    gw = _router_url(ctx)
    isp = ctx.get("isp")
    if fid == "wifi_default_ssid":
        return ("Cambia el nombre y la contraseña de la Wi-Fi.",
                [f"Entra en {gw} (o en la app de {isp}) → Wi-Fi.",
                 "Pon un nombre que no revele el operador ni tu nombre, y una contraseña nueva de 12 caracteres o más.",
                 "Hazlo en las dos bandas (2,4 GHz y 5 GHz). Tendrás que volver a conectar tus dispositivos."], [])
    if fid == "wifi_wpa2":
        return ("Activa WPA3 (o WPA2/WPA3 mixto) si el router lo permite.",
                [f"En {gw} → Wi-Fi → Seguridad, elige 'WPA2/WPA3-Personal'.",
                 "El modo mixto mantiene compatibles los dispositivos antiguos."]
                + ([f"En routers de {isp} la opción puede no estar disponible según el modelo y el firmware."] if isp else []), [])
    if fid in ("wifi_open", "wifi_wep", "wifi_tkip"):
        return ("Configura WPA2-AES o WPA3 con una contraseña robusta.",
                [f"En {gw} → Wi-Fi → Seguridad: WPA2-Personal (AES/CCMP) o WPA3.", "Usa una contraseña de 12 caracteres o más."], [])
    if fid == "evil_twin":
        return ("No te conectes a la red con seguridad distinta y vigila dónde se conectan tus dispositivos.",
                ["En tus dispositivos, olvida la red y vuelve a conectarte comprobando que pide contraseña.",
                 "Si persiste, cambia el nombre de tu Wi-Fi a uno único.",
                 "BSSID sospechosos: " + ", ".join(f.get("bssids") or []) or "—"], [])
    if fid == "arp_spoof":
        return ("Comprueba qué equipo tiene esa MAC.",
                ["Busca la MAC en la lista de clientes del router.",
                 "Si es un repetidor o puente Wi-Fi puede ser normal. Si no lo reconoces, desconéctalo y cambia la contraseña de la Wi-Fi."],
                [{"label": "Ver la tabla ARP", "code": "arp -a"}])
    if fid == "router_upnp":
        return ("Desactiva UPnP en el router.", _router_steps(ctx, "Busca UPnP (Red / NAT / Avanzado) y desactívalo."), [])
    if fid == "upnp_forward":
        m = f.get("mapping") or {}
        return (f"Cierra el puerto {m.get('external_port')} si no lo necesitas.",
                _router_steps(ctx, f"En NAT / Reenvío de puertos / UPnP elimina la regla hacia {m.get('internal_ip')}:{m.get('internal_port')}."), [])
    if fid == "dns_plain":
        return ("Usa un DNS con filtrado de malware.",
                ["Lo mejor es cambiarlo en el router (afecta a toda la red); si no se puede, cámbialo en cada equipo.",
                 "Opciones: Quad9 9.9.9.9 / 149.112.112.112 o Cloudflare 1.1.1.2 / 1.0.0.2."]
                + ([f"Muchos routers de {isp} no permiten cambiar el DNS: en ese caso, cámbialo en tus equipos."] if isp else []),
                [{"label": "Este equipo (PowerShell administrador)", "code":
                  f"Set-DnsClientServerAddress -InterfaceAlias '{ctx.get('interface') or 'Wi-Fi'}' -ServerAddresses 9.9.9.9,149.112.112.112"}])
    if fid == "ipv6_global":
        return ("Comprueba que el firewall IPv6 del router está activo.", _router_steps(ctx, "En IPv6 / Firewall, verifica que bloquea conexiones entrantes."), [])
    return None


def _local(fid, f, ctx):
    ps = "PowerShell (administrador)"
    table = {
        "win10_eol": ("Actualiza a Windows 11 o activa las actualizaciones extendidas (ESU).",
                      ["Configuración → Windows Update → comprueba si tu equipo puede actualizar a Windows 11."], []),
        "fw_off": ("Activa el firewall de Windows.", ["Seguridad de Windows → Firewall y protección de red → actívalo en todos los perfiles."],
                   [{"label": ps, "code": "Set-NetFirewallProfile -All -Enabled True"}]),
        "av_off": ("Activa la protección en tiempo real.", ["Seguridad de Windows → Protección antivirus y contra amenazas → Administrar configuración."],
                   [{"label": ps, "code": "Set-MpPreference -DisableRealtimeMonitoring $false"}]),
        "av_old": ("Actualiza las firmas del antivirus.", [], [{"label": "PowerShell", "code": "Update-MpSignature"}]),
        "tamper_off": ("Activa la protección contra alteraciones.",
                       ["Seguridad de Windows → Protección antivirus → Administrar configuración → Protección contra alteraciones: Activado."], []),
        "smb1": _smb1(None, ctx, "self_windows"),
        "smb_signing": ("Exige firma SMB.", ["Protege frente a ataques de retransmisión NTLM en la red local."],
                        [{"label": ps, "code": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\n"
                                                "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"}]),
        "rdp_local": _rdp({"ip": "este equipo"}, ctx, "self_windows"),
        "uac_off": ("Activa el Control de cuentas de usuario.", ["Panel de control → Cuentas de usuario → Cambiar configuración de Control de cuentas."],
                    [{"label": ps, "code": "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"}]),
        "uac_silent": ("Haz que el UAC pida confirmación.", [],
                       [{"label": ps, "code": "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -Value 5"}]),
        "updates_old": ("Instala las actualizaciones pendientes.", ["Configuración → Windows Update → Buscar actualizaciones."],
                        [{"label": "Abrir Windows Update", "code": "start ms-settings:windowsupdate"}]),
        "guest_on": ("Desactiva la cuenta Invitado.", [], [{"label": ps, "code": "Get-LocalUser | Where-Object SID -like '*-501' | Disable-LocalUser"}]),
        "bitlocker_off": ("Activa el cifrado del disco.", ["Configuración → Privacidad y seguridad → Cifrado del dispositivo (o BitLocker en Pro)."],
                          [{"label": ps, "code": "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -RecoveryPasswordProtector"}]),
        "net_private": ("Márcala como pública cuando estés fuera de casa.", [],
                        [{"label": ps, "code": f"Set-NetConnectionProfile -InterfaceAlias '{ctx.get('interface') or 'Wi-Fi'}' -NetworkCategory Public"}]),
    }
    if fid == "listening":
        items = f.get("listening") or []
        cmds = [{"label": "Ver qué programa usa cada puerto (PowerShell)", "code":
                 "Get-NetTCPConnection -State Listen | Where-Object LocalAddress -in '0.0.0.0','::' |\n"
                 "  Select-Object LocalPort, @{n='Proceso';e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Sort-Object LocalPort"}]
        steps = ["Revisa si reconoces cada programa. Si es una herramienta de desarrollo, configúrala para escuchar solo en 127.0.0.1."]
        if any(x.get("process") == "System" for x in items):
            steps.append("Los puertos del proceso 'System' suelen ser servicios HTTP de Windows (http.sys) registrados por otras apps: "
                         "`netsh http show servicestate` muestra cuál.")
            cmds.append({"label": "Ver qué app registró los puertos de http.sys", "code": "netsh http show servicestate"})
        return ("Cierra o limita los servicios que no necesites.", steps, cmds)
    return table.get(fid)


DEVICE_HANDLERS = {
    "smb1": _smb1, "rdp": _rdp, "telnet": _telnet, "upnp": _upnp, "tls_selfsigned": _tls_selfsigned,
    "tls_nofs": _tls_nofs,
}
DEVICE_HANDLERS_F = {"db_exposed": _db, "cve": _cve}

GENERIC = {
    "ftp_anon": ("Desactiva el acceso anónimo al FTP.", ["vsftpd: anonymous_enable=NO · ProFTPD: elimina el bloque <Anonymous>."], []),
    "ftp_plain": ("Sustituye FTP por SFTP.", ["SFTP funciona sobre SSH y cifra credenciales y archivos."], []),
    "smb_share": ("Revisa qué carpetas compartes.", ["Comprueba que ninguna permite acceso de invitado o 'Todos'."],
                  [{"label": "En Windows: ver recursos compartidos", "code": "Get-SmbShare | Format-Table Name, Path, Description"}]),
    "vnc": ("Desactiva VNC o limítalo a túnel SSH/VPN.", ["Configura VNC para escuchar solo en localhost y conéctate por túnel SSH."],
            [{"label": "Túnel SSH desde tu equipo", "code": "ssh -L 5901:localhost:5900 usuario@IP"}]),
    "adb": ("Desactiva la depuración por red.", ["Ajustes → Opciones de desarrollador → desactiva 'Depuración inalámbrica' y 'Depuración USB'."], []),
    "winrm": ("Desactiva WinRM si no administras ese equipo en remoto.", [], [{"label": "PowerShell (administrador) en ese PC", "code": "Disable-PSRemoting -Force\nStop-Service WinRM; Set-Service WinRM -StartupType Disabled"}]),
    "backdoor_port": ("Investiga qué programa usa el puerto 4444.", ["Si no lo reconoces, desconecta el equipo de la red y analízalo con un antivirus."],
                      [{"label": "En Windows", "code": "Get-NetTCPConnection -LocalPort 4444 | Select-Object OwningProcess"}]),
    "redis_noauth": ("Activa contraseña en Redis y enlázalo a localhost.", [],
                     [{"label": "redis.conf", "code": "bind 127.0.0.1 ::1\nprotected-mode yes\nrequirepass UNA_CONTRASEÑA_LARGA"}]),
    "elastic_noauth": ("Activa la seguridad de Elasticsearch.", [],
                       [{"label": "elasticsearch.yml", "code": "xpack.security.enabled: true\nnetwork.host: 127.0.0.1"}]),
    "docker_api": ("Cierra el socket TCP de Docker.", ["Quita '-H tcp://0.0.0.0:2375' de la configuración del demonio, o usa TLS mutuo en 2376."],
                   [{"label": "bash", "code": "sudo systemctl edit docker   # elimina -H tcp://...\nsudo systemctl restart docker"}]),
    "rtsp": ("Protege la cámara.", ["Cambia la contraseña por defecto, desactiva el acceso P2P/nube si no lo usas y actualiza el firmware."], []),
    "mqtt": ("Activa autenticación y TLS en el broker.", [],
             [{"label": "mosquitto.conf", "code": "allow_anonymous false\npassword_file /etc/mosquitto/passwd\nlistener 8883\ncertfile /etc/mosquitto/certs/server.crt\nkeyfile /etc/mosquitto/certs/server.key"}]),
    "tr069": ("Si el router es del operador, TR-069 es normal; si es tuyo, desactívalo.", [], []),
    "snmp_public": ("Desactiva SNMP o cambia la comunidad 'public'.", ["En el panel del equipo: SNMP → desactivar, o usar SNMPv3 con usuario y contraseña."], []),
    "http_login": ("Accede al panel por HTTPS.", ["Activa HTTPS en la configuración del equipo y desactiva el acceso HTTP."], []),
    "tls_expired": ("Renueva el certificado.", [], []),
    "tls_old": ("Acepta solo TLS 1.2 y 1.3.", ["Actualiza el firmware o la configuración del servidor."], []),
    "new_device": ("Comprueba que reconoces el dispositivo.", ["Mira la lista de clientes del router y su fabricante (MAC).",
                   "Si no sabes qué es, cambia la contraseña de la Wi-Fi."], []),
}


def apply(f: dict, host: dict | None, ctx: dict) -> dict:
    """Rellena fix/steps/commands/context del hallazgo según el dispositivo."""
    fid = f["id"]
    p = profile(host)
    res = None
    if host is None:
        res = _network(fid, f, ctx) if f.get("scope") == "network" else _local(fid, f, ctx)
    elif fid in DEVICE_HANDLERS:
        res = DEVICE_HANDLERS[fid](host, ctx, p)
    elif fid in DEVICE_HANDLERS_F:
        res = DEVICE_HANDLERS_F[fid](host, ctx, p, f)
    elif fid == "server_version":
        res = _server_version({**host, "_port": f.get("port")}, ctx, p)
    if res is None:
        res = GENERIC.get(fid, ("Revisa la configuración de este servicio.", [], []))
    f["fix"], f["steps"], f["commands"] = res
    ctx_text = describe(host, ctx) if host else ("Configuración de tu red" if f.get("scope") == "network" else "Este equipo")
    if ctx_text:
        f["context"] = ctx_text
    return f
