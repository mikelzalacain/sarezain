"""Límites de seguridad: Sarezain solo escanea redes privadas y de tamaño acotado."""

import ipaddress

MIN_PREFIX = 22  # como máximo /22 (1022 hosts)


class UnsafeTargetError(ValueError):
    """El objetivo no es una red privada permitida."""


def validate_network(cidr: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise UnsafeTargetError(f"Red no válida: {cidr}") from exc

    if not isinstance(net, ipaddress.IPv4Network):
        raise UnsafeTargetError("Solo se admiten redes IPv4.")
    if not net.is_private or net.is_loopback or net.is_link_local or net.is_multicast:
        raise UnsafeTargetError(
            f"{net} no es una red privada. Sarezain solo escanea redes locales "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
        )
    if net.prefixlen < MIN_PREFIX:
        raise UnsafeTargetError(
            f"{net} es demasiado grande. El máximo permitido es /{MIN_PREFIX}."
        )
    return net
