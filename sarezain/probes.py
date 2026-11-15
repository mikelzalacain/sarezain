"""Sondas de servicio: identifican producto/versión y comprueban configuraciones.

Todas las comprobaciones son pasivas o de solo lectura: no se explota nada ni se
prueban contraseñas. La única "autenticación" es el acceso anónimo de FTP, que es
público por diseño cuando está activado.
"""

from __future__ import annotations

import asyncio
import os
import re
import ssl
import tempfile
from datetime import datetime, timezone

from .ports import HTTP_PORTS, HTTPS_PORTS, SERVICES

TIMEOUT = 3.0
UA = "Sarezain/0.1 (auditoria de red local)"


async def _open(ip: str, port: int, tls: bool = False):
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        # Nivel 0: permite hablar con equipos antiguos para poder auditarlos.
        # Solo se usa para leer certificado/cabeceras, nunca para enviar datos sensibles.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx), TIMEOUT)


async def _read(reader: asyncio.StreamReader, n: int = 2048, timeout: float = TIMEOUT) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout)
    except (asyncio.TimeoutError, OSError):
        return b""


async def _read_all(reader: asyncio.StreamReader, limit: int = 65536) -> bytes:
    buf = b""
    while len(buf) < limit:
        chunk = await _read(reader, 8192)
        if not chunk:
            break
        buf += chunk
    return buf


def _close(writer) -> None:
    try:
        writer.close()
    except Exception:
        pass


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


# ---------------------------------------------------------------- versiones

PRODUCT_PATTERNS = [
    (r"OpenSSH[_-]([\w.]+)", "OpenSSH"),
    (r"dropbear[_-]([\w.]+)", "Dropbear SSH"),
    (r"vsFTPd ([\d.]+)", "vsftpd"),
    (r"ProFTPD ([\d.]+)", "ProFTPD"),
    (r"FileZilla Server(?: version)? ([\d.]+)", "FileZilla Server"),
    (r"Pure-FTPd", "Pure-FTPd"),
    (r"Postfix", "Postfix"),
    (r"Exim ([\d.]+)", "Exim"),
    (r"Microsoft FTP Service", "Microsoft FTP"),
]


def parse_product(text: str) -> tuple[str | None, str | None]:
    for pattern, name in PRODUCT_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return name, (m.group(1) if m.groups() else None)
    return None, None


def parse_server_header(server: str) -> tuple[str | None, str | None]:
    m = re.match(r"\s*([A-Za-z][\w\-. ]*?)/(\d[\w.\-]*)", server)
    if m:
        return m.group(1).strip(), m.group(2)
    return (server.strip()[:60] or None), None


# ---------------------------------------------------------------- TLS

def _decode_cert(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # API interna, estable desde Python 3.4
    except Exception:
        return {}
    finally:
        os.unlink(path)


def _cert_summary(der: bytes | None) -> dict | None:
    if not der:
        return None
    cert = _decode_cert(der)
    if not cert:
        return None

    def name(field):
        parts = dict(x[0] for x in cert.get(field, ()) if x)
        return parts.get("commonName") or parts.get("organizationName")

    not_after = cert.get("notAfter")
    expires = None
    if not_after:
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
        except ValueError:
            pass
    return {
        "subject": name("subject"),
        "issuer": name("issuer"),
        "self_signed": cert.get("subject") == cert.get("issuer"),
        "expires": expires.isoformat() if expires else None,
        "expired": bool(expires and expires < datetime.now(timezone.utc)),
    }


# ---------------------------------------------------------------- HTTP

async def probe_http(ip: str, port: int, tls: bool) -> dict:
    info: dict = {"tls": tls}
    try:
        reader, writer = await _open(ip, port, tls)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        info["error"] = type(exc).__name__
        return info
    try:
        if tls:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj:
                info["tls_version"] = sslobj.version()
                info["cipher"] = (sslobj.cipher() or (None,))[0]
                info["certificate"] = _cert_summary(sslobj.getpeercert(binary_form=True))
        writer.write(f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n"
                     "Connection: close\r\n\r\n".encode())
        await writer.drain()
        raw = await _read_all(reader)
    except (OSError, ssl.SSLError):
        raw = b""
    finally:
        _close(writer)

    head, _, body = raw.partition(b"\r\n\r\n")
    lines = _text(head).splitlines()
    if not lines:
        return info
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", lines[0])
    info["status"] = int(m.group(1)) if m else None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    info["headers"] = {k: headers[k] for k in
                       ("server", "x-powered-by", "location", "www-authenticate",
                        "strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options") if k in headers}
    body_text = body[:65536].decode("utf-8", errors="replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
    info["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:120] if title else None
    info["login_form"] = bool(re.search(r"type\s*=\s*['\"]?password", body_text, re.IGNORECASE))
    info["basic_auth"] = "basic" in headers.get("www-authenticate", "").lower()
    if "server" in headers:
        info["product"], info["version"] = parse_server_header(headers["server"])
    return info


# ---------------------------------------------------------------- servicios concretos

async def probe_banner(ip: str, port: int, send: bytes | None = None) -> dict:
    try:
        reader, writer = await _open(ip, port)
    except (OSError, asyncio.TimeoutError):
        return {}
    try:
        if send:
            writer.write(send)
            await writer.drain()
        data = await _read(reader)
    finally:
        _close(writer)
    banner = _text(data)[:200]
    product, version = parse_product(banner)
    return {"banner": banner or None, "product": product, "version": version}


async def probe_ftp(ip: str, port: int) -> dict:
    info: dict = {}
    try:
        reader, writer = await _open(ip, port)
    except (OSError, asyncio.TimeoutError):
        return info
    try:
        banner = _text(await _read(reader))
        info["banner"] = banner[:200] or None
        info["product"], info["version"] = parse_product(banner)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp = _text(await _read(reader))
        if resp.startswith("331"):
            writer.write(b"PASS sarezain@example.com\r\n")
            await writer.drain()
            resp = _text(await _read(reader))
        info["anonymous"] = resp.startswith("230")
        writer.write(b"QUIT\r\n")
    except OSError:
        pass
    finally:
        _close(writer)
    return info


SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x2f"                      # NetBIOS session, longitud 47
    b"\xffSMB\x72"                           # SMB1, comando NEGOTIATE
    b"\x00\x00\x00\x00\x18\x01\x28"          # status, flags, flags2
    b"\x00\x00" + b"\x00" * 8 + b"\x00\x00"  # pid alto, firma, reservado
    b"\x00\x00\x2f\x4b\x00\x00\xc5\x5e"      # tid, pid, uid, mid
    b"\x00\x0c\x00\x02NT LM 0.12\x00"        # wordcount, bytecount, dialecto
)


async def probe_smb(ip: str, port: int) -> dict:
    """Comprueba si el equipo acepta el protocolo SMBv1 (obsoleto, WannaCry)."""
    try:
        reader, writer = await _open(ip, port)
    except (OSError, asyncio.TimeoutError):
        return {}
    try:
        writer.write(SMB1_NEGOTIATE)
        await writer.drain()
        resp = await _read(reader, 512)
    except OSError:
        resp = b""
    finally:
        _close(writer)
    smb1 = (len(resp) >= 39 and resp[4:8] == b"\xffSMB" and resp[9:13] == b"\x00\x00\x00\x00"
            and resp[37:39] != b"\xff\xff")
    return {"smb1": smb1}


async def probe_redis(ip: str, port: int) -> dict:
    info = await probe_banner(ip, port, b"PING\r\n")
    banner = info.get("banner") or ""
    return {"no_auth": banner.startswith("+PONG"), "banner": banner[:60] or None}


async def probe_mysql(ip: str, port: int) -> dict:
    try:
        reader, writer = await _open(ip, port)
    except (OSError, asyncio.TimeoutError):
        return {}
    try:
        data = await _read(reader, 512)
    finally:
        _close(writer)
    if len(data) > 6 and data[4] == 10:
        version = data[5:data.index(b"\x00", 5)].decode("ascii", errors="replace") if b"\x00" in data[5:] else None
        product = "MariaDB" if version and "mariadb" in version.lower() else "MySQL"
        return {"product": product, "version": version.split("-")[0] if version else None}
    return {}


async def probe_json_api(ip: str, port: int, path: str) -> dict:
    """GET a una API HTTP sin autenticación (Docker, Elasticsearch)."""
    try:
        reader, writer = await _open(ip, port)
    except (OSError, asyncio.TimeoutError):
        return {}
    try:
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        raw = await _read_all(reader, 16384)
    finally:
        _close(writer)
    head, _, body = raw.partition(b"\r\n\r\n")
    ok = head.startswith(b"HTTP/") and b" 200 " in head.split(b"\r\n")[0]
    body_text = _text(body)
    version = re.search(r'"(?:Version|number)"\s*:\s*"([\w.\-]+)"', body_text)
    return {"open_api": ok and body_text.startswith("{"), "version": version.group(1) if version else None}


# ---------------------------------------------------------------- despachador

async def probe_port(ip: str, port: int) -> dict:
    result: dict = {"port": port, "service": SERVICES.get(port, "desconocido")}
    try:
        if port in HTTPS_PORTS:
            result.update(await probe_http(ip, port, tls=True))
        elif port == 2375:
            result.update(await probe_json_api(ip, port, "/version"))
        elif port == 9200:
            result.update(await probe_json_api(ip, port, "/"))
        elif port in HTTP_PORTS:
            result.update(await probe_http(ip, port, tls=False))
        elif port == 21:
            result.update(await probe_ftp(ip, port))
        elif port in (445,):
            result.update(await probe_smb(ip, port))
        elif port == 6379:
            result.update(await probe_redis(ip, port))
        elif port == 3306:
            result.update(await probe_mysql(ip, port))
        elif port in (22, 23, 25, 110, 143, 587, 5900, 5901):
            result.update(await probe_banner(ip, port))
            if port in (5900, 5901) and (result.get("banner") or "").startswith("RFB"):
                result["product"], result["version"] = "VNC", result["banner"][4:11]
    except Exception as exc:  # una sonda nunca debe tumbar el escaneo
        result["error"] = type(exc).__name__
    return {k: v for k, v in result.items() if v not in (None, "", {})}
