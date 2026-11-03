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


def resolve_public_all(host: str, port: int) -> list[str]:
    """Resolve `host`; return all its addresses, or raise PrivateHost if any
    address is not public. DNS errors propagate as OSError."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = list(dict.fromkeys(i[4][0] for i in infos))
    if not addrs or not all(_is_public(a) for a in addrs):
        raise PrivateHost(host)
    return addrs


def resolve_public(host: str, port: int) -> str:
    return resolve_public_all(host, port)[0]


def pin(host: str, port: int) -> list[str] | None:
    """The checked addresses to dial for `host` when the guard is on, else None."""
    return resolve_public_all(host, port) if _enabled else None


def connect(addrs: list[str], port: int, timeout=None, source_address=None) -> socket.socket:
    """Like socket.create_connection over a host's checked addresses: try each
    in order (a host may publish IPv6 first on a network without IPv6)."""
    err: OSError | None = None
    for addr in addrs:
        try:
            return socket.create_connection((addr, port), timeout, source_address)
        except OSError as e:
            err = e
    raise err or OSError(f"no address to connect to on port {port}")
