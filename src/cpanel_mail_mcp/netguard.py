"""Keep mailbox connections off the server's own network.

In multi-user HTTP mode students choose their own IMAP/SMTP hosts, so a host
that resolves to loopback, a private range, link-local, CGNAT… would let them
probe the server's network. When enabled, every mailbox connection resolves
the host once, refuses non-global addresses, and dials exactly the address it
checked (TLS still verifies the certificate against the host *name*), so a
DNS answer that changes between check and connect can't slip through.
"""
from __future__ import annotations

import ipaddress
import socket

_enabled = False


class PrivateHost(OSError):
    def __init__(self, host: str) -> None:
        super().__init__(f"{host} does not resolve to a public Internet address")
        self.host = host


def configure(enabled: bool) -> None:
    global _enabled
    _enabled = enabled


def _is_public(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int) -> str:
    """Resolve `host`; return its first address, or raise PrivateHost if any
    address is not public. DNS errors propagate as OSError."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [i[4][0] for i in infos]
    if not addrs or not all(_is_public(a) for a in addrs):
        raise PrivateHost(host)
    return addrs[0]


def pin(host: str, port: int) -> str | None:
    """The address to dial for `host` when the guard is on, else None."""
    return resolve_public(host, port) if _enabled else None
