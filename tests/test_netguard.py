"""Non-ASCII logins, pinned connections and TLS verification for mailbox hosts."""
import imaplib
import smtplib
import socket
import ssl

import pytest

from cpanel_mail_mcp import imap_ops, netguard, smtp_ops
from cpanel_mail_mcp.accounts import _from_dict

from .mini_servers import MiniIMAP, MiniSMTP


def _acct(**over):
    d = {"user": "ana@ex.com", "password": "contraseña", "host": "mail.ex.com"}
    d.update(over)
    return _from_dict(d)


@pytest.mark.parametrize("pw", ["contraseña", "plain-ascii"])
def test_imap_login_through_real_imaplib(pw):
    srv = MiniIMAP()
    m = imaplib.IMAP4("127.0.0.1", srv.port)
    imap_ops._login(m, _acct(password=pw))
    m.logout()
    assert srv.auth == ("ana@ex.com", pw)


@pytest.mark.parametrize("pw", ["contraseña", "plain-ascii"])
def test_smtp_login_through_real_smtplib(pw):
    srv = MiniSMTP()
    s = smtplib.SMTP("127.0.0.1", srv.port, timeout=5)
    s.ehlo()
    smtp_ops._login(s, _acct(password=pw))
    s.quit()
    assert srv.auth == ("ana@ex.com", pw)


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "172.17.0.1", "192.168.1.1",
                                  "169.254.169.254", "100.64.1.1", "::1", "0.0.0.0",
                                  "::ffff:127.0.0.1"])
def test_resolve_public_rejects_non_global(monkeypatch, addr):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [(fam, 1, 6, "", (addr, p))])
    with pytest.raises(netguard.PrivateHost):
        netguard.resolve_public("evil.example", 993)


def test_resolve_public_returns_checked_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda h, p, *a, **k: [(socket.AF_INET, 1, 6, "", ("93.184.216.34", p))])
    assert netguard.resolve_public("mail.ex.com", 993) == "93.184.216.34"


@pytest.fixture
def guard_on(monkeypatch):
    monkeypatch.setattr(netguard, "_enabled", True)


def _rebinding(monkeypatch, first="93.184.216.34", then="127.0.0.1"):
    """First lookup answers public, every later one internal (TTL-0 rebinding)."""
    answers = [first]

    def gai(h, p, *a, **k):
        addr = answers.pop(0) if answers else then
        return [(socket.AF_INET, 1, 6, "", (addr, p))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    dialed = []

    def create_connection(address, *a, **k):
        dialed.append(address)
        raise ConnectionRefusedError("test stops here")
    monkeypatch.setattr(socket, "create_connection", create_connection)
    return dialed


def test_imap_connect_dials_the_checked_ip(guard_on, monkeypatch):
    dialed = _rebinding(monkeypatch)
    with pytest.raises(OSError):
        imap_ops._connect(_acct())
    assert dialed == [("93.184.216.34", 993)]


def test_smtp_connect_dials_the_checked_ip(guard_on, monkeypatch):
    for port in (465, 587):
        dialed = _rebinding(monkeypatch)
        with pytest.raises(OSError):
            smtp_ops._connect(_acct(smtp_port=port))
        assert dialed and dialed[0][0] == "93.184.216.34"


def test_connect_refuses_private_host_when_guarded(guard_on, monkeypatch):
    dialed = _rebinding(monkeypatch, first="10.0.0.1")
    with pytest.raises(netguard.PrivateHost):
        imap_ops._connect(_acct())
    assert dialed == []


def test_guard_off_by_default_allows_private(monkeypatch):
    assert netguard.pin("10.0.0.1", 993) is None


def test_imap_verifies_tls_certificates(monkeypatch):
    seen = {}

    class Capture:
        def __init__(self, host, port, *, ssl_context=None, timeout=None):
            seen["ctx"] = ssl_context
            raise ConnectionRefusedError("stop")
    monkeypatch.setattr(imaplib, "IMAP4_SSL", Capture)
    with pytest.raises(OSError):
        imap_ops._connect(_acct())
    assert seen["ctx"].verify_mode == ssl.CERT_REQUIRED and seen["ctx"].check_hostname


def test_pinned_connect_falls_back_to_next_checked_address(guard_on, monkeypatch):
    """Host publishes IPv6 first but the container has no IPv6: try the IPv4 too."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [
        (socket.AF_INET6, 1, 6, "", ("2606:4700::1", p, 0, 0)),
        (socket.AF_INET, 1, 6, "", ("93.184.216.34", p))])
    dialed = []

    def create_connection(address, *a, **k):
        dialed.append(address[0])
        raise OSError(101, "Network is unreachable")
    monkeypatch.setattr(socket, "create_connection", create_connection)
    with pytest.raises(OSError):
        imap_ops._connect(_acct())
    assert dialed == ["2606:4700::1", "93.184.216.34"]
    dialed.clear()
    with pytest.raises(OSError):
        smtp_ops._connect(_acct())
    assert dialed == ["2606:4700::1", "93.184.216.34"]
