"""Signup page: a student registers their mailbox and gets an API key."""
import json
import re
import socket

import anyio
import httpx
import pytest

from cpanel_mail_mcp import signup, users as users_mod, vault
from cpanel_mail_mcp.mailcheck import LoginThrottle, MailboxInfo, MailboxRejected

CODE = "curso-2026"


async def _inner(scope, receive, send):
    await send({"type": "http.response.start", "status": 401, "headers": []})
    await send({"type": "http.response.body", "body": b"inner"})


@pytest.fixture
def env(tmp_path, monkeypatch):
    users_file = tmp_path / "users.json"
    monkeypatch.setenv("EMAIL_USERS_FILE", str(users_file))
    calls = []
    state = {"fail": None}

    def verify(acct, *, check_smtp):
        calls.append((acct, check_smtp))
        if state["fail"]:
            raise state["fail"]
        return MailboxInfo("Enviados", "Borradores", None, True)

    resolved = {"addr": "93.184.216.34"}

    def fake_getaddrinfo(host, port, *a, **kw):
        addr = resolved.get(host, resolved["addr"])
        fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, "", (addr, port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    app = signup.SignupASGI(_inner, code=CODE, fernet=vault.load_key(),
                            public_url="https://imap-mcp.example", verify=verify,
                            throttle=LoginThrottle(), code_throttle=LoginThrottle(max_per_user=10))
    return type("Env", (), {"app": app, "calls": calls, "state": state,
                            "resolved": resolved, "users_file": users_file})


def _req(app, method, path="/alta", **kw):
    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://t") as c:
            return await c.request(method, path, **kw)
    return anyio.run(go)


def _form(**over):
    d = {"codigo": CODE, "email": "Ana@Ex.com", "password": "pw", "imap_host": "mail.ex.com",
         "imap_port": "993", "smtp_host": "", "smtp_port": "465", "from_name": ""}
    d.update(over)
    return d


def _key(html: str) -> str:
    return re.search(r'<code id="api-key">([^<]+)</code>', html).group(1)


def test_get_form(env):
    r = _req(env.app, "GET")
    assert r.status_code == 200
    assert 'name="codigo"' in r.text and 'name="password"' in r.text
    assert r.headers["cache-control"] == "no-store"


def test_other_paths_pass_through(env):
    assert _req(env.app, "GET", "/mcp").text == "inner"


def test_wrong_code_403(env):
    r = _req(env.app, "POST", data=_form(codigo="nope"))
    assert r.status_code == 403
    assert env.calls == []


def test_signup_creates_encrypted_entry(env):
    r = _req(env.app, "POST", data=_form())
    assert r.status_code == 200, r.text
    key = _key(r.text)
    assert "https://imap-mcp.example/mcp" in r.text
    assert "Authorization: Bearer {{ api_key }}" in r.text
    assert r.headers["cache-control"] == "no-store"
    users = users_mod.load_users()
    acct = users[vault.hash_token(key)]
    assert acct.user == "ana@ex.com"
    assert acct.sent_folder == "Enviados" and acct.drafts_folder == "Borradores"
    assert acct.smtp_host == "mail.ex.com"
    assert "pw\"" not in env.users_file.read_text() and key not in env.users_file.read_text()
    assert env.calls[0][1] is False  # no SMTP host given → SMTP not checked


def test_smtp_checked_when_given(env):
    r = _req(env.app, "POST", data=_form(smtp_host="smtp.ex.com", smtp_port="587"))
    assert r.status_code == 200
    acct, check_smtp = env.calls[0]
    assert check_smtp is True and acct.smtp_host == "smtp.ex.com" and acct.smtp_port == 587


def test_password_special_chars_roundtrip(env):
    pw = "a&b=c+d%e ñ"
    assert _req(env.app, "POST", data=_form(password=pw)).status_code == 200
    assert env.calls[0][0].password == pw
    assert next(iter(users_mod.load_users().values())).password == pw


def test_resignup_replaces_and_revokes(env):
    k1 = _key(_req(env.app, "POST", data=_form()).text)
    r = _req(env.app, "POST", data=_form(email="ANA@EX.COM", password="new"))
    assert r.status_code == 200
    assert "ha dejado de funcionar" in r.text
    k2 = _key(r.text)
    users = users_mod.load_users()
    assert list(users) == [vault.hash_token(k2)]
    assert users[vault.hash_token(k2)].password == "new"
    assert vault.hash_token(k1) not in users


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "172.18.0.2", "192.168.1.1",
                                  "169.254.169.254", "::1", "0.0.0.0"])
def test_rejects_internal_hosts(env, addr):
    env.resolved["addr"] = addr
    r = _req(env.app, "POST", data=_form())
    assert r.status_code == 400
    assert env.calls == []
    assert not env.users_file.exists()


def test_rejects_internal_smtp_host(env):
    env.resolved["smtp.internal"] = "10.1.2.3"
    r = _req(env.app, "POST", data=_form(smtp_host="smtp.internal"))
    assert r.status_code == 400 and env.calls == []


@pytest.mark.parametrize("field,value", [("email", "no-at"), ("email", "a@b.com\r\nX: y"),
                                         ("imap_host", "bad host"), ("imap_port", "0"),
                                         ("imap_port", "70000"), ("smtp_port", "abc"),
                                         ("password", "")])
def test_invalid_fields_400(env, field, value):
    r = _req(env.app, "POST", data=_form(**{field: value}))
    assert r.status_code == 400 and env.calls == []


def test_bad_password_message_and_throttle(env):
    env.state["fail"] = MailboxRejected("imap")
    for _ in range(5):
        r = _req(env.app, "POST", data=_form())
        assert r.status_code == 400
        assert "contraseña de aplicación" in r.text
    r = _req(env.app, "POST", data=_form())
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    assert len(env.calls) == 5


def test_wrong_code_throttled_per_ip(env):
    for _ in range(10):
        _req(env.app, "POST", data=_form(codigo="x"), headers={"x-real-ip": "1.2.3.4"})
    assert _req(env.app, "POST", data=_form(), headers={"x-real-ip": "1.2.3.4"}).status_code == 429
    assert _req(env.app, "POST", data=_form(), headers={"x-real-ip": "5.6.7.8"}).status_code == 200


def test_unreachable_502(env):
    from cpanel_mail_mcp.mailcheck import MailServerUnreachable
    env.state["fail"] = MailServerUnreachable("imap")
    r = _req(env.app, "POST", data=_form())
    assert r.status_code == 422 and "mail.ex.com:993" in r.text


def test_html_escaped(env):
    r = _req(env.app, "POST", data=_form(from_name="<script>x</script>", imap_port="0"))
    assert "<script>x</script>" not in r.text


def test_body_too_large_413(env):
    r = _req(env.app, "POST", content=b"a=" + b"x" * 9000,
             headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413


def test_resignup_with_other_host_is_refused(env):
    k1 = _key(_req(env.app, "POST", data=_form()).text)
    r = _req(env.app, "POST", data=_form(imap_host="evil.example", password="whatever"))
    assert r.status_code == 409
    assert len(env.calls) == 1  # the second attempt never reached verify
    assert list(users_mod.load_users()) == [vault.hash_token(k1)]


def test_resignup_same_host_other_case_allowed(env):
    _req(env.app, "POST", data=_form())
    assert _req(env.app, "POST", data=_form(imap_host="MAIL.EX.COM")).status_code == 200


def test_rejects_cgnat(env):
    env.resolved["addr"] = "100.64.1.1"
    assert _req(env.app, "POST", data=_form()).status_code == 400 and env.calls == []


def test_code_is_case_and_space_insensitive(env):
    assert _req(env.app, "POST", data=_form(codigo="  CURSO-2026 ")).status_code == 200


def test_correct_code_clears_ip_failures(env):
    app = signup.SignupASGI(_inner, code=CODE, fernet=vault.load_key(), public_url="https://x",
                            verify=lambda a, check_smtp: MailboxInfo("S", "D", None, True),
                            code_throttle=LoginThrottle(max_per_user=3))
    h = {"x-real-ip": "1.2.3.4"}
    for _ in range(2):
        _req(app, "POST", data=_form(codigo="typo"), headers=h)
    assert _req(app, "POST", data=_form(), headers=h).status_code == 200
    for _ in range(2):
        _req(app, "POST", data=_form(codigo="typo"), headers=h)
    assert _req(app, "POST", data=_form(email="b@ex.com"), headers=h).status_code == 200


def test_global_cap_has_its_own_message(env):
    env.state["fail"] = MailboxRejected("imap")
    env.app._throttle = LoginThrottle(max_per_user=5, max_global=3)
    for i in range(3):
        _req(env.app, "POST", data=_form(email=f"u{i}@ex.com"))
    r = _req(env.app, "POST", data=_form(email="fresh@ex.com"))
    assert r.status_code == 429
    assert "con este correo" not in r.text and "muchos intentos" in r.text.lower()


def test_default_limits_fit_a_class():
    app = signup.SignupASGI(_inner, code=CODE, fernet=vault.load_key(), public_url="https://x")
    assert app._throttle.max_global >= 300
    assert app._code_throttle.max_user >= 20


def test_unreachable_counts_as_failure(env):
    from cpanel_mail_mcp.mailcheck import MailServerUnreachable
    env.state["fail"] = MailServerUnreachable("imap")
    for _ in range(5):
        assert _req(env.app, "POST", data=_form()).status_code == 422
    assert _req(env.app, "POST", data=_form()).status_code == 429


def test_certificate_error_message(env):
    from cpanel_mail_mcp.mailcheck import MailServerUnreachable
    env.state["fail"] = MailServerUnreachable("imap", cert_error=True)
    r = _req(env.app, "POST", data=_form())
    assert r.status_code == 422 and "certificado" in r.text
