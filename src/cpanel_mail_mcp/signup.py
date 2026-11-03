"""Self-service signup page (`/alta`) for course students.

A student enters the course code and their mailbox settings; the server
tries the IMAP (and SMTP, if given) login, detects the folders, stores the
account encrypted in users.json and shows the API key once, with the steps
to paste it into Langdock. Repeating the signup for the same mailbox
replaces the entry and revokes the previous key.

Enabled by `MCP_SIGNUP_CODE` (the course code) in multi-user mode.
"""
from __future__ import annotations

import hmac
import html
import logging
import re
from typing import Callable
from urllib.parse import parse_qs

import anyio
from cryptography.fernet import Fernet

from . import mailcheck, netguard, users as users_mod
from .accounts import _from_dict
from .mailcheck import LoginThrottle, MailboxRejected, MailServerUnreachable, Throttled

log = logging.getLogger("cpanel_mail_mcp.signup")

PATHS = ("/alta", "/alta/")
MAX_BODY = 8 * 1024
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class _Bad(Exception):
    """A form error shown to the student (status, message)."""

    def __init__(self, status: int, message: str, headers: list | None = None) -> None:
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers or []


_CSS = """
:root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1d1d1b;--muted:#5d5d58;--card:#fff;--line:#d8d8d2;--accent:#2f6b3a;--err:#a3261b}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ececea;--muted:#a5a59f;--card:#21211f;--line:#3a3a36;--accent:#7fc28a;--err:#ff8b7f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:34rem;margin:0 auto;padding:2rem 1rem}h1{font-size:1.5rem;margin:0 0 .5rem}
p.lead{color:var(--muted);margin:0 0 1.5rem}form,.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1.25rem}
label{display:block;font-weight:600;margin:.9rem 0 .25rem}label small{font-weight:400;color:var(--muted)}
input{width:100%;padding:.55rem .65rem;font:inherit;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.row{display:grid;grid-template-columns:1fr 6.5rem;gap:.75rem}fieldset{border:0;padding:0;margin:1.25rem 0 0}
legend{font-weight:700;padding:0}button{margin-top:1.5rem;width:100%;padding:.75rem;font:inherit;font-weight:700;border:0;border-radius:6px;background:var(--accent);color:var(--bg);cursor:pointer}
.err{border:1px solid var(--err);color:var(--err);border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem}
code{font-family:ui-monospace,monospace;word-break:break-all}#api-key{display:block;padding:.75rem;border:1px dashed var(--accent);border-radius:6px;margin:.5rem 0 1rem;font-size:.95rem}
ol{padding-left:1.25rem}li{margin:.35rem 0}.warn{color:var(--err);font-weight:600}
"""


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
        f"<body><main>{body}</main></body></html>"
    ).encode()


def _form_html(values: dict[str, str] | None = None, error: str = "") -> bytes:
    v = {"imap_port": "993", "smtp_port": "465", **(values or {})}

    def val(k: str) -> str:
        return html.escape(v.get(k, ""), quote=True)

    err = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    body = f"""
<h1>Conectar tu correo</h1>
<p class="lead">Da de alta tu buzón para usarlo desde el asistente de correo. Al terminar
recibirás una clave para pegar en Langdock.</p>
{err}
<form method="post" action="/alta" accept-charset="utf-8" autocomplete="off">
  <label for="codigo">Código del curso</label>
  <input id="codigo" name="codigo" required>
  <label for="email">Correo electrónico <small>(tu usuario IMAP)</small></label>
  <input id="email" name="email" type="email" required value="{val('email')}">
  <label for="password">Contraseña <small>(mejor una contraseña de aplicación)</small></label>
  <input id="password" name="password" type="password" required>
  <fieldset><legend>Servidor de entrada (IMAP)</legend>
    <div class="row">
      <div><label for="imap_host">Servidor</label>
        <input id="imap_host" name="imap_host" required placeholder="mail.tudominio.com" value="{val('imap_host')}"></div>
      <div><label for="imap_port">Puerto</label>
        <input id="imap_port" name="imap_port" inputmode="numeric" required value="{val('imap_port')}"></div>
    </div>
  </fieldset>
  <fieldset><legend>Servidor de salida (SMTP) <small>— solo si quieres enviar correo</small></legend>
    <div class="row">
      <div><label for="smtp_host">Servidor</label>
        <input id="smtp_host" name="smtp_host" placeholder="smtp.tudominio.com" value="{val('smtp_host')}"></div>
      <div><label for="smtp_port">Puerto</label>
        <input id="smtp_port" name="smtp_port" inputmode="numeric" value="{val('smtp_port')}"></div>
    </div>
  </fieldset>
  <label for="from_name">Nombre del remitente <small>(opcional)</small></label>
  <input id="from_name" name="from_name" value="{val('from_name')}">
  <button type="submit">Dar de alta</button>
</form>"""
    return _page("Alta de correo", body)


def _success_html(key: str, public_url: str, email: str, replaced: bool) -> bytes:
    revoked = ('<p class="warn">Ya tenías un alta con este correo: la clave anterior ha dejado '
               'de funcionar. Usa esta nueva.</p>') if replaced else ""
    body = f"""
<h1>Correo conectado</h1>
<div class="card">
<p>Buzón <strong>{html.escape(email)}</strong> verificado. Esta es tu clave:</p>
<code id="api-key">{html.escape(key)}</code>
<p class="warn">Cópiala ahora: no se vuelve a mostrar. Si la pierdes, repite el alta.</p>
{revoked}
<p>Para usarla en Langdock:</p>
<ol>
  <li>Abre la integración de correo del workspace y pulsa <em>Añadir conexión</em>.</li>
  <li>Comprueba que la URL es <code>{html.escape(public_url)}/mcp</code> y que la autenticación es
      por API key con la cabecera <code>Authorization: Bearer {{{{ api_key }}}}</code>.</li>
  <li>Pega la clave de arriba y guarda.</li>
</ol>
</div>"""
    return _page("Correo conectado", body)


def _check_public(host: str, port: int) -> None:
    """Friendly early rejection; the connection itself is pinned by netguard."""
    try:
        netguard.resolve_public(host, port)
    except netguard.PrivateHost:
        raise _Bad(400, f"El servidor {host} no es una dirección pública de Internet.") from None
    except OSError:
        raise _Bad(400, f"No se encuentra el servidor {host}. Revisa el nombre.") from None


def _port(raw: str, field: str) -> int:
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise _Bad(400, f"El puerto {field} no es válido.")
    return int(raw)


def _parse(fields: dict[str, str]) -> dict:
    email = fields.get("email", "").strip().lower()
    if ("@" not in email or len(email) > 254 or any(c in email for c in "\r\n\0 \t")):
        raise _Bad(400, "El correo electrónico no es válido.")
    password = fields.get("password", "")
    if not password or len(password) > 1024:
        raise _Bad(400, "Falta la contraseña.")
    imap_host = fields.get("imap_host", "").strip()
    smtp_host = fields.get("smtp_host", "").strip()
    for h in filter(None, (imap_host, smtp_host)):
        if not _HOST_RE.match(h):
            raise _Bad(400, f"El servidor «{h}» no es válido.")
    if not imap_host:
        raise _Bad(400, "Falta el servidor IMAP.")
    return {
        "email": email,
        "password": password,
        "imap_host": imap_host,
        "imap_port": _port(fields.get("imap_port", "993").strip() or "993", "IMAP"),
        "smtp_host": smtp_host,
        "smtp_port": _port(fields.get("smtp_port", "465").strip() or "465", "SMTP"),
        "from_name": fields.get("from_name", "").strip()[:200] or None,
    }


def _norm_code(code: str) -> bytes:
    return code.strip().casefold().encode()


def _throttled(e: Throttled) -> _Bad:
    msg = ("Demasiados intentos fallidos con este correo. Prueba más tarde." if e.scope == "user"
           else "Hay muchos intentos fallidos en este momento. Espera unos minutos y vuelve a probar.")
    return _Bad(429, msg, [(b"retry-after", str(e.retry_after).encode())])


class SignupASGI:
    def __init__(self, app, *, code: str, fernet: Fernet, public_url: str,
                 verify: Callable = mailcheck.verify_mailbox,
                 throttle: LoginThrottle | None = None,
                 code_throttle: LoginThrottle | None = None) -> None:
        self.app = app
        self._code = _norm_code(code)
        self._fernet = fernet
        self._public_url = public_url.rstrip("/")
        self._verify = verify
        # per mailbox + overall; sized for a whole class signing up at once
        self._throttle = throttle or LoginThrottle(max_per_user=5, max_global=300)
        # wrong course codes per client IP (a classroom may share one NAT IP)
        self._code_throttle = code_throttle or LoginThrottle(max_per_user=20, max_global=1000)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") not in PATHS:
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "GET")
        if method in ("GET", "HEAD"):
            await self._respond(send, 200, _form_html())
        elif method == "POST":
            await self._post(scope, receive, send)
        else:
            await self._respond(send, 405, _form_html(), [(b"allow", b"GET, POST")])

    async def _respond(self, send, status: int, body: bytes, extra: list | None = None) -> None:
        headers = [(b"content-type", b"text/html; charset=utf-8"), (b"cache-control", b"no-store"),
                   (b"x-frame-options", b"DENY"), *(extra or [])]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    def _client_ip(scope) -> str:
        for k, v in scope.get("headers", []):
            if k == b"x-real-ip" and v:
                return v.decode("latin-1").strip()
        client = scope.get("client")
        return client[0] if client else "?"

    async def _read_body(self, receive) -> bytes | None:
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if len(body) > MAX_BODY:
                return None
            if not msg.get("more_body"):
                return body

    async def _post(self, scope, receive, send):
        raw = await self._read_body(receive)
        if raw is None:
            await self._respond(send, 413, _form_html(error="Formulario demasiado grande."))
            return
        fields = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace"),
                                                keep_blank_values=True).items()}
        shown = {k: v for k, v in fields.items() if k not in ("password", "codigo")}
        try:
            status, body = await self._handle(fields, self._client_ip(scope))
            await self._respond(send, status, body)
        except _Bad as e:
            await self._respond(send, e.status, _form_html(shown, e.message), e.headers)

    async def _handle(self, fields: dict[str, str], ip: str) -> tuple[int, bytes]:
        try:
            self._code_throttle.check(ip)
        except Throttled as e:
            raise _throttled(e) from None
        if not hmac.compare_digest(_norm_code(fields.get("codigo", "")), self._code):
            self._code_throttle.failure(ip)
            raise _Bad(403, "El código del curso no es correcto.")
        self._code_throttle.success(ip)

        f = _parse(fields)
        try:
            self._throttle.check(f["email"])
        except Throttled as e:
            raise _throttled(e) from None
        existing = await anyio.to_thread.run_sync(users_mod.registered_host, f["email"])
        if existing is not None and existing.lower() != f["imap_host"].lower():
            raise _Bad(409, "Este correo ya está dado de alta con otro servidor IMAP. Para "
                            "cambiarlo, pide al responsable del curso que borre el alta anterior.")

        check_smtp = bool(f["smtp_host"])
        smtp_host = f["smtp_host"] or f["imap_host"]
        account = {
            "name": f["email"], "user": f["email"], "password": f["password"],
            "imap_host": f["imap_host"], "imap_port": f["imap_port"],
            "smtp_host": smtp_host, "smtp_port": f["smtp_port"],
            "from_name": f["from_name"],
        }

        def check() -> mailcheck.MailboxInfo:
            _check_public(f["imap_host"], f["imap_port"])
            if check_smtp:
                _check_public(smtp_host, f["smtp_port"])
            return self._verify(_from_dict(account), check_smtp=check_smtp)

        try:
            info = await anyio.to_thread.run_sync(check)
        except MailboxRejected as e:
            self._throttle.failure(f["email"])
            log.info("alta rechazada: %s (%s)", f["email"], e.protocol)
            name = "IMAP" if e.protocol == "imap" else "SMTP"
            raise _Bad(400, f"El servidor {name} ha rechazado el usuario o la contraseña. Si tu "
                            "proveedor lo permite, usa una contraseña de aplicación.") from None
        except MailServerUnreachable as e:
            self._throttle.failure(f["email"])
            host, port = ((f["imap_host"], f["imap_port"]) if e.protocol == "imap"
                          else (smtp_host, f["smtp_port"]))
            log.info("alta sin conexión: %s (%s %s:%s)", f["email"], e.protocol, host, port)
            if e.cert_error:
                raise _Bad(422, f"El certificado de seguridad de {host} no corresponde a ese nombre. "
                                "Usa el nombre de servidor que indica tu proveedor (a veces es el "
                                "del hosting, no mail.tudominio).") from None
            raise _Bad(422, f"No se ha podido conectar con {host}:{port}. Revisa el servidor y el "
                            "puerto que indica tu proveedor para IMAP (suele ser imap.…, puerto 993).") from None

        self._throttle.success(f["email"])
        account.update(sent_folder=info.sent_folder, drafts_folder=info.drafts_folder,
                       save_to_sent=info.save_to_sent)
        if info.trash_folder:
            account["trash_folder"] = info.trash_folder
        key = users_mod.new_token()
        try:
            replaced = await anyio.to_thread.run_sync(
                users_mod.upsert_user, users_mod.make_entry(key, account, self._fernet))
        except users_mod.HostMismatch:  # registered on another host meanwhile
            raise _Bad(409, "Este correo ya está dado de alta con otro servidor IMAP.") from None
        log.info("alta ok: %s (%s)", f["email"], "sustituida" if replaced else "nueva")
        return 200, _success_html(key, self._public_url, f["email"], replaced)
