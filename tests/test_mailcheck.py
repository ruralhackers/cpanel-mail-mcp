"""mailcheck: verify a mailbox before saving it, detect its folders, throttle failures."""
import smtplib

import pytest

from cpanel_mail_mcp import imap_ops, mailcheck, smtp_ops
from cpanel_mail_mcp.accounts import _from_dict
from cpanel_mail_mcp.mailcheck import (
    LoginThrottle, MailboxRejected, MailServerUnreachable, Throttled, verify_mailbox,
)

from .fake_imap import FakeServer


def _acct(**over):
    d = {"user": "ana@ex.com", "password": "pw", "host": "mail.ex.com"}
    d.update(over)
    return _from_dict(d)


class _SMTP:
    def quit(self):
        pass


@pytest.fixture
def server(monkeypatch):
    s = FakeServer()
    s.passwords["ana@ex.com"] = "pw"
    monkeypatch.setattr(imap_ops, "_connect", s.connect)
    smtp_calls = []

    def fake_smtp(a):
        smtp_calls.append(a)
        return _SMTP()
    monkeypatch.setattr(smtp_ops, "_connect", fake_smtp)
    s.smtp_calls = smtp_calls
    return s


def test_special_use_wins(server):
    server.add_folder("INBOX.Sent")
    server.add_folder("Enviados", special="\\Sent")
    server.add_folder("Borradores", special="\\Drafts")
    server.add_folder("Papelera", special="\\Trash")
    info = verify_mailbox(_acct(), check_smtp=False)
    assert info.sent_folder == "Enviados"
    assert info.drafts_folder == "Borradores"
    assert info.trash_folder == "Papelera"
    assert info.save_to_sent is True


def test_name_fallback_spanish(server):
    server.add_folder("INBOX.Enviados")
    server.add_folder("INBOX.Borradores")
    info = verify_mailbox(_acct(), check_smtp=False)
    assert info.sent_folder == "INBOX.Enviados"
    assert info.drafts_folder == "INBOX.Borradores"


def test_no_sent_folder_disables_save_to_sent(server):
    info = verify_mailbox(_acct(), check_smtp=False)
    assert (info.sent_folder, info.drafts_folder) == ("Sent", "Drafts")
    assert info.save_to_sent is False


def test_gmail_disables_save_to_sent(server):
    server.add_folder("[Gmail]/Sent Mail", special="\\Sent")
    info = verify_mailbox(_acct(imap_host="imap.gmail.com"), check_smtp=False)
    assert info.sent_folder == "[Gmail]/Sent Mail"
    assert info.save_to_sent is False


def test_bad_imap_password(server):
    with pytest.raises(MailboxRejected) as e:
        verify_mailbox(_acct(password="wrong"), check_smtp=True)
    assert e.value.protocol == "imap"
    assert server.smtp_calls == []


def test_bad_smtp_password(server, monkeypatch):
    def reject(a):
        raise smtplib.SMTPAuthenticationError(535, b"bad")
    monkeypatch.setattr(smtp_ops, "_connect", reject)
    with pytest.raises(MailboxRejected) as e:
        verify_mailbox(_acct(), check_smtp=True)
    assert e.value.protocol == "smtp"


def test_smtp_checked_when_requested(server):
    verify_mailbox(_acct(), check_smtp=True)
    assert len(server.smtp_calls) == 1


def test_smtp_skipped_when_not_requested(server):
    verify_mailbox(_acct(), check_smtp=False)
    assert server.smtp_calls == []


def test_imap_unreachable(monkeypatch):
    def down(a):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(imap_ops, "_connect", down)
    with pytest.raises(MailServerUnreachable) as e:
        verify_mailbox(_acct(), check_smtp=False)
    assert e.value.protocol == "imap"


def test_smtp_unreachable(server, monkeypatch):
    def down(a):
        raise TimeoutError("timeout")
    monkeypatch.setattr(smtp_ops, "_connect", down)
    with pytest.raises(MailServerUnreachable) as e:
        verify_mailbox(_acct(), check_smtp=True)
    assert e.value.protocol == "smtp"


def test_throttle_per_user_and_global():
    now = [1000.0]
    t = LoginThrottle(max_per_user=5, max_global=50, window_seconds=900, clock=lambda: now[0])
    for _ in range(5):
        t.check("a@x")
        t.failure("a@x")
    with pytest.raises(Throttled) as e:
        t.check("a@x")
    assert 1 <= e.value.retry_after <= 900
    t.check("b@x")  # other users unaffected
    now[0] += 901
    t.check("a@x")  # window expired


def test_throttle_global():
    t = LoginThrottle(max_per_user=5, max_global=50, window_seconds=900, clock=lambda: 0.0)
    for i in range(50):
        t.failure(f"u{i}@x")
    with pytest.raises(Throttled):
        t.check("fresh@x")


def test_throttle_success_clears_user():
    t = LoginThrottle(max_per_user=2, max_global=50, window_seconds=900, clock=lambda: 0.0)
    t.failure("a@x")
    t.success("a@x")
    t.failure("a@x")
    t.check("a@x")


def test_certificate_error_is_flagged(monkeypatch):
    import ssl
    def bad_cert(a):
        raise ssl.SSLCertVerificationError("hostname mismatch")
    monkeypatch.setattr(imap_ops, "_connect", bad_cert)
    with pytest.raises(MailServerUnreachable) as e:
        verify_mailbox(_acct(), check_smtp=False)
    assert e.value.cert_error is True
