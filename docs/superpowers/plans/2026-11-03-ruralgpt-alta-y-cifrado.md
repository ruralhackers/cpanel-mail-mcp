# ruralgpt: alta de alumnos y credenciales cifradas — Plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convertir el fork `ruralhackers/cpanel-mail-mcp` en el conector IMAP multicuenta de ruralgpt.gal (Langdock): cada alumno se da de alta en una página web con los datos de su buzón, recibe una API key y la pega en Langdock; el servidor guarda sus credenciales cifradas.

**Architecture:** Se parte del modo multiusuario existente (`users.json` + `Authorization: Bearer <token>` → `Account`). Se recortan los modos que no usamos (CF Access/OAuth, credentials), se cifra la contraseña en reposo con Fernet y se guarda solo el hash del token, y se añade un middleware ASGI `/alta` que verifica el buzón contra IMAP (y SMTP opcional) antes de crear la entrada.

**Tech Stack:** Python ≥3.10, SDK oficial `mcp` (FastMCP, Streamable HTTP), uvicorn, `cryptography` (Fernet), imaplib/smtplib de stdlib, pytest + httpx.

**Spec:** `~/Downloads/Conector IMAP multicuenta para ruralgpt.gal.pdf` (opción A: API key por alumno) y la revisión del repo hecha en la conversación del 2026-11-03.

## Global Constraints

- Las contraseñas de buzón nunca se escriben en claro en disco ni en logs.
- El token (API key) solo se muestra una vez, en la respuesta del alta o del CLI; en disco solo va su SHA-256.
- Clave de cifrado en la variable `MCP_USERS_KEY` (clave Fernet, urlsafe base64 de 32 bytes). Sin ella, el modo multiusuario no arranca.
- El alta está desactivada salvo que exista `MCP_SIGNUP_CODE` (código del curso, compartido en clase).
- Solo IMAP sobre TLS (`IMAP4_SSL`); SMTP 465 implícito o STARTTLS en cualquier otro puerto (comportamiento actual de `smtp_ops._connect`).
- Textos de la página de alta en español.
- Langdock se configura con cabecera `Authorization: Bearer {{ api_key }}` contra `https://<host>/mcp`.
- `pytest` en verde al final de cada tarea.

## Review Focus

1. **Host del alumno que apunta a la red interna** (`localhost`, `10.x`, `172.16/12`, `192.168/16`, nombre de un contenedor Docker): el alta debe rechazarlo antes de conectar, o la página sirve para sondear el VPS. → test en Tarea 4.
2. **Alumno que repite el alta** (perdió la key o cambió la contraseña): debe sustituir su entrada y revocar la key anterior, no duplicar ni fallar. → test en Tarea 4.
3. **`MCP_USERS_KEY` incorrecta o rotada** con `users.json` existente: el arranque debe fallar con un mensaje claro; en caliente, el store conserva el último mapa bueno. → test en Tarea 2.
4. **Contraseña con caracteres raros** (`&`, `=`, `+`, `%`, tildes, espacios) enviada por formulario: debe llegar intacta a IMAP. → test en Tarea 4.
5. **Fuerza bruta contra el alta** (código del curso o contraseñas de buzón ajenas): límite por email y global. → test en Tarea 4.

---

### Tarea 0 (manual, antes de tocar código): prueba de humo con Langdock

Objetivo: confirmar que Langdock habla con este servidor antes de invertir en cambios. Si falla, parar y replantear.

- [ ] En el VPS (o en local con un túnel HTTPS), arrancar el upstream tal cual en modo multiusuario con una cuenta de prueba:
  `EMAIL_USERS_FILE=/tmp/u.json cpanel-mail-mcp admin add-user --email prueba@… --host mail.…` y luego `MCP_TRANSPORT=http EMAIL_USERS_FILE=/tmp/u.json cpanel-mail-mcp`.
- [ ] En Langdock: integración MCP con URL `https://<host>/mcp`, auth por API key, cabecera `Authorization: Bearer {{ api_key }}`; pegar el token.
- [ ] Verificar: aparecen las 22 herramientas; `list_folders` y `list_recent` devuelven datos; `send_email` pide confirmación si se activa "Request confirmation".
- [ ] Apuntar en el PR cualquier rareza (p. ej. si Langdock exige `/.well-known/…`, lo que cambiaría la Tarea 1).

---

### Tarea 1: Recortar CF Access, proxy OAuth y modo credentials

Menos superficie que auditar (RGPD) y menos código que entender en las tareas siguientes.

**Files:**
- Delete: `src/cpanel_mail_mcp/cf_access.py`, `src/cpanel_mail_mcp/oauth_proxy.py`, `src/cpanel_mail_mcp/passthrough.py`, `tests/test_passthrough.py`
- Modify: `src/cpanel_mail_mcp/server.py` (imports, `UnifiedAuthASGI`, `CredentialsAuthASGI`, `WellKnownASGI`, `_set_www_authenticate`, `_user_by_email`, `create_http_app`)
- Modify: `src/cpanel_mail_mcp/accounts.py` (quitar `sso_emails`), `src/cpanel_mail_mcp/admin.py` (quitar `--sso-email`, `add-sso-email`, `remove-sso-email`)
- Modify: `tests/test_server_wellknown.py`, `tests/test_users.py`, `pyproject.toml` (quitar `pyjwt[crypto]`)

**Interfaces:**
- Produces: `UnifiedAuthASGI(app, *, users: UsersStore | dict[str, Account] | None = None, single_token: str | None = None)`; `HealthASGI(app)` (sustituye a `WellKnownASGI`, solo sirve `/health` y `/healthz`); `_is_public_path(path) -> bool` devuelve True solo para `/health`, `/healthz`.
- `MCP_AUTH_MODE` desaparece; `create_http_app` elige multiusuario (`EMAIL_USERS_FILE`), single-tenant (`MCP_AUTH_TOKEN`) o `MCP_ALLOW_NO_AUTH`.

- [ ] **Step 1: Adaptar tests**: en `test_server_wellknown.py` borrar `test_protected_resource_metadata` y `test_path_suffixed_metadata_also_works`; renombrar `test_mcp_without_auth_returns_401_with_resource_metadata` a `test_mcp_without_auth_returns_401` con `assert r.headers["www-authenticate"] == 'Bearer realm="mcp"'`; quitar `MCP_RESOURCE_URL` del entorno del fixture. En `test_users.py` borrar `test_add_sso_email` y `test_remove_sso_email`. Añadir en `tests/test_server_wellknown.py`:

```python
def test_oauth_endpoints_are_gone(running_server):
    port = running_server
    assert httpx.get(f"http://127.0.0.1:{port}/.well-known/oauth-protected-resource").status_code == 401
    assert httpx.post(f"http://127.0.0.1:{port}/register").status_code == 401
```

- [ ] **Step 2:** `.venv/bin/pytest tests/test_server_wellknown.py -v` → FAIL en `test_oauth_endpoints_are_gone` (hoy devuelve 200) y en el header.
- [ ] **Step 3: Borrar los módulos y simplificar `server.py`** según Interfaces. `grep -rn "cf_access\|oauth_proxy\|passthrough\|sso_email\|MCP_AUTH_MODE\|MCP_RESOURCE_URL" src tests deploy README.md Dockerfile docker-compose.yml` debe quedar vacío salvo CHANGELOG.
- [ ] **Step 4:** `.venv/bin/pip install -e . && .venv/bin/pytest` → todo PASS.
- [ ] **Step 5: Commit** `refactor: drop CF Access, OAuth proxy and credentials mode`

---

### Tarea 2: Contraseñas cifradas y token hasheado en `users.json`

**Files:**
- Create: `src/cpanel_mail_mcp/vault.py`, `tests/conftest.py`, `tests/test_vault.py`
- Modify: `src/cpanel_mail_mcp/users.py`, `src/cpanel_mail_mcp/admin.py`, `src/cpanel_mail_mcp/server.py` (`_user_by_token`, arranque multiusuario), `pyproject.toml` (añadir `cryptography>=42`)
- Modify tests: `tests/test_users.py`, `tests/test_security.py`, `tests/test_http_multiuser.py`, `tests/test_server_wellknown.py` (los fixtures escriben entradas con `users.make_entry`)

**Interfaces:**
- `vault.load_key() -> cryptography.fernet.Fernet` — lee `MCP_USERS_KEY`; `SystemExit("MCP_USERS_KEY …")` si falta o no es una clave Fernet válida.
- `vault.hash_token(token: str) -> str` — SHA-256 hex.
- `vault.encrypt(f: Fernet, plaintext: str) -> str` / `vault.decrypt(f: Fernet, token: str) -> str` (lanza `ValueError` si no descifra).
- `users.make_entry(token: str, account: dict, f: Fernet) -> dict` — devuelve `{"token_sha256": hash_token(token), "account": {...account sin "password", "password_enc": encrypt(f, password)}}`.
- Formato de entrada en disco: `{"token_sha256": "<hex>", "account": {"user": …, "password_enc": "<fernet>", …}}`. Una entrada con `token` o `account.password` en claro hace que `load_users` lance `ValueError("…plaintext entry…")`.
- `users.load_users(path=None, f: Fernet | None = None) -> dict[str, Account]` — **clave = hash del token**; `f` por defecto `vault.load_key()`.
- `users.UsersStore(path, f: Fernet | None = None)`.
- `users.is_multi_user() -> bool` — True si `EMAIL_USERS_FILE` está definida (aunque el fichero aún no exista; `load_users` devuelve `{}` en ese caso). Lo necesita el contenedor de la Tarea 5 al arrancar vacío.
- `server._user_by_token(users, token) -> Account | None` = `users.get(vault.hash_token(token))`.
- admin `list-users` muestra `token_sha256[:8]`; `add-user` y `rotate-token` imprimen el token una vez y guardan solo el hash.

- [ ] **Step 1: Tests.** `tests/conftest.py` con fixture `autouse` que hace `monkeypatch.setenv("MCP_USERS_KEY", Fernet.generate_key().decode())` (los tests con subprocess heredan `os.environ`). `tests/test_vault.py`:

```python
def test_roundtrip_and_hash():
    f = vault.load_key()
    assert vault.decrypt(f, vault.encrypt(f, "pä&ss= +%")) == "pä&ss= +%"
    assert vault.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()

def test_missing_or_bad_key_exits(monkeypatch):
    monkeypatch.delenv("MCP_USERS_KEY")
    with pytest.raises(SystemExit): vault.load_key()
    monkeypatch.setenv("MCP_USERS_KEY", "nope")
    with pytest.raises(SystemExit): vault.load_key()

def test_file_has_no_plaintext(users_file):   # en test_users.py
    admin.main(["add-user", "--email", "j@d.com", "--password", "s3cr3t-pw", "--host", "h"])
    raw = users_file.read_text()
    assert "s3cr3t-pw" not in raw and '"token"' not in raw and "token_sha256" in raw

def test_plaintext_entry_rejected(tmp_path):
    p = tmp_path / "u.json"
    p.write_text(json.dumps([{"token": "t"*30, "account": {"user": "a@x", "password": "p", "host": "h"}}]))
    with pytest.raises(ValueError, match="plaintext"): users_mod.load_users(p)

def test_wrong_key_keeps_last_good_map(tmp_path, monkeypatch):
    # save con clave A, UsersStore carga; reescribir el fichero cifrado con clave B → store.get() devuelve el mapa anterior
```

  En `test_http_multiuser.py` el fixture escribe `users.make_entry(...)` y `test_rotate_add_remove_apply_without_restart` cambia `token_sha256` en vez de `token`. `test_users_store_reloads_on_change` compara contra `vault.hash_token(...)`.
- [ ] **Step 2:** `.venv/bin/pytest` → FAIL (no existe `vault`).
- [ ] **Step 3: Implementar** según Interfaces. `create_http_app` llama a `vault.load_key()` antes de construir el store para fallar al arrancar.
- [ ] **Step 4:** `.venv/bin/pytest` → PASS.
- [ ] **Step 5: Commit** `feat: encrypt mailbox passwords and store only token hashes`

---

### Tarea 3: Verificación de buzón y autodetección de carpetas

**Files:**
- Create: `src/cpanel_mail_mcp/mailcheck.py`, `tests/test_mailcheck.py`

**Interfaces:**
- `class MailboxRejected(Exception)` con atributo `protocol: Literal["imap", "smtp"]`; `class MailServerUnreachable(Exception)` con `protocol`.
- `@dataclass(frozen=True) class MailboxInfo: sent_folder: str; drafts_folder: str; trash_folder: str | None; save_to_sent: bool`
- `verify_mailbox(acct: Account, *, check_smtp: bool) -> MailboxInfo` — bloqueante. IMAP: `imap_ops._connect` + `imap_ops._list`; `imaplib.IMAP4.error` → `MailboxRejected("imap")`, `OSError` → `MailServerUnreachable("imap")`. SMTP (si `check_smtp`): `smtp_ops._connect`; `smtplib.SMTPAuthenticationError` → `MailboxRejected("smtp")`, `OSError`/`SMTPException` → `MailServerUnreachable("smtp")`.
- Carpetas: primero SPECIAL-USE (`\Sent`, `\Drafts`, `\Trash` en `flags`), luego candidatos por nombre sin distinguir mayúsculas — Sent: `INBOX.Sent`, `Sent`, `Sent Items`, `INBOX.Sent Items`, `Sent Messages`, `[Gmail]/Sent Mail`, `Enviados`, `INBOX.Enviados`, `Elementos enviados`; Drafts: `INBOX.Drafts`, `Drafts`, `[Gmail]/Drafts`, `Borradores`, `INBOX.Borradores`. Se guarda el `name` decodificado (la misma forma que devuelve `list_folders`). Sin coincidencia: `Sent` / `Drafts`. Trash: `imap_ops._detect_trash` sobre la misma lista.
- `save_to_sent = False` si `imap_host` es `imap.gmail.com` u `outlook.office365.com` (esos servidores ya guardan lo enviado por SMTP; un APPEND lo duplicaría), o si no se encontró carpeta Sent; si no, True.
- `class LoginThrottle(max_per_user=5, max_global=50, window_seconds=900)` con `check(user: str) -> None` (lanza `Throttled(retry_after: int)`), `failure(user: str) -> None`, `success(user: str) -> None`. Usa `time.monotonic`; inyectable `clock: Callable[[], float]` para tests.

- [ ] **Step 1: Tests** con `tests/fake_imap.py` (ya existe) o monkeypatch de `imap_ops._connect`/`_list` y `smtp_ops._connect`:
  - `test_special_use_wins` — lista con `INBOX.Sent` y `Enviados (\Sent)` → `sent_folder == "Enviados"`.
  - `test_name_fallback_spanish` — sin flags, `INBOX.Enviados` / `INBOX.Borradores` detectados.
  - `test_gmail_disables_save_to_sent` — `imap_host="imap.gmail.com"` → `save_to_sent is False`.
  - `test_bad_imap_password` → `MailboxRejected` con `protocol == "imap"`; `test_bad_smtp_password` → `protocol == "smtp"`; `test_smtp_skipped_when_not_requested` (no se llama a `smtp_ops._connect`).
  - `test_unreachable` (`OSError`) → `MailServerUnreachable`.
  - `test_throttle_per_user_and_global` — 5 fallos de `a@x` → `check("a@x")` lanza, `check("b@x")` no; tras avanzar el reloj 900 s vuelve a pasar; 50 fallos repartidos → lanza para cualquiera.
- [ ] **Step 2:** `.venv/bin/pytest tests/test_mailcheck.py -v` → FAIL.
- [ ] **Step 3: Implementar** `mailcheck.py`.
- [ ] **Step 4:** `.venv/bin/pytest` → PASS.
- [ ] **Step 5: Commit** `feat: mailbox verification with folder auto-detection`

---

### Tarea 4: Página de alta `/alta`

**Files:**
- Create: `src/cpanel_mail_mcp/signup.py`, `tests/test_signup.py`
- Modify: `src/cpanel_mail_mcp/server.py` (`create_http_app` envuelve la app ya autenticada con `SignupASGI`, por fuera de `UnifiedAuthASGI` y por dentro de `HealthASGI`, cuando hay `MCP_SIGNUP_CODE` y modo multiusuario; así `/alta` no pasa por auth y `_is_public_path` no cambia), `src/cpanel_mail_mcp/users.py` (`upsert_user`)

**Interfaces:**
- Consumes: `users.make_entry`, `users.load_users_raw`, `users.save_users`, `users.new_token`, `vault.load_key` (Tarea 2); `mailcheck.verify_mailbox`, `MailboxRejected`, `MailServerUnreachable`, `LoginThrottle`, `Throttled` (Tarea 3).
- `users.upsert_user(entry: dict) -> bool` — bajo un `threading.Lock` de módulo: carga, sustituye la entrada con el mismo `account.user` (minúsculas) o la añade, guarda. Devuelve True si sustituyó.
- `class SignupASGI(app, *, code: str, fernet: Fernet, public_url: str, verify=mailcheck.verify_mailbox, throttle: LoginThrottle | None = None)`:
  - `GET /alta` → 200, formulario HTML.
  - `POST /alta` (`application/x-www-form-urlencoded`, cuerpo > 8 KiB → 413) con campos `codigo`, `email`, `password`, `imap_host`, `imap_port` (993), `smtp_host` (vacío = no se usa SMTP para enviar y no se verifica; se guarda `smtp_host = imap_host`), `smtp_port` (465), `from_name` (opcional).
  - Cualquier otra ruta → `app`.
- Orden de comprobaciones en el POST: `throttle.check("*")` global → código (`hmac.compare_digest`; si falla, `throttle.failure("*")` y 403) → validación de campos (email ≤254 con `@` y sin `\r\n\0 `; hosts que casan con `^[A-Za-z0-9.-]{1,253}$`; puertos 1–65535) → `throttle.check(email)` → resolución DNS (`socket.getaddrinfo`) de `imap_host` y `smtp_host`: rechazar (400) si alguna dirección es `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast` o `is_unspecified` → `verify_mailbox` en hilo (`anyio.to_thread.run_sync`) → `make_entry` + `upsert_user` → página de éxito.
- Respuestas (todas `text/html; charset=utf-8`, `Cache-Control: no-store`, valores repetidos con `html.escape`):
  - Éxito 200: muestra la key una vez, la URL `{public_url}/mcp`, y los pasos de Langdock (auth por API key, cabecera `Authorization: Bearer {{ api_key }}`, pegar la key). Si `upsert_user` sustituyó: «La clave anterior ha dejado de funcionar».
  - `MailboxRejected` 400: «El servidor IMAP/SMTP ha rechazado el usuario o la contraseña. Si tu proveedor lo permite, usa una contraseña de aplicación.» + `throttle.failure(email)` + `throttle.failure("*")`.
  - `MailServerUnreachable` 502: «No se ha podido conectar con {host}:{port}».
  - `Throttled` 429 con `Retry-After`.
- Logs: solo `alta ok: <email> (nueva|sustituida)` y fallos sin contraseña.
- Entorno: `MCP_SIGNUP_CODE` (activa), `MCP_PUBLIC_URL` (obligatoria si hay código; `SystemExit` si falta).

- [ ] **Step 1: Tests** en `tests/test_signup.py`, llamando al ASGI con `httpx.ASGITransport` y un `verify` falso que devuelve `MailboxInfo("Enviados", "Borradores", None, True)`; `getaddrinfo` parcheado para devolver `93.184.216.34` salvo en los tests de red interna:
  - `test_get_form` — 200 y contiene `name="codigo"`.
  - `test_wrong_code_403` — y `verify` no se llama.
  - `test_signup_creates_encrypted_entry` — 200; la key de la página autentica (`users.load_users()` contiene `vault.hash_token(key)` con `sent_folder == "Enviados"`); el fichero no contiene la contraseña.
  - `test_password_special_chars_roundtrip` — contraseña `"a&b=c+d%e ñ"` llega idéntica a `verify` (Review Focus 4).
  - `test_resignup_replaces_and_revokes` — segunda alta del mismo email (en mayúsculas): una sola entrada, la key vieja ya no está, la página dice «ha dejado de funcionar» (Review Focus 2).
  - `test_rejects_internal_hosts` — parametrizado con `127.0.0.1`, `10.0.0.5`, `172.18.0.2`, `192.168.1.1`, `169.254.169.254`, `::1` → 400 y `verify` no se llama (Review Focus 1).
  - `test_bad_password_throttled` — `verify` lanza `MailboxRejected("imap")`; 5 intentos → el sexto 429 (Review Focus 5).
  - `test_html_escaped` — `from_name="<script>"` no aparece sin escapar.
  - `test_body_too_large_413`.
  - En `tests/test_server_wellknown.py`: `test_alta_disabled_without_code` — `GET /alta` → 401 (pasa por auth, no existe).
- [ ] **Step 2:** `.venv/bin/pytest tests/test_signup.py -v` → FAIL.
- [ ] **Step 3: Implementar** `signup.py`, `upsert_user` y el cableado en `create_http_app`. HTML inline, sin JS, CSS mínimo legible en móvil.
- [ ] **Step 4:** `.venv/bin/pytest` → PASS. Prueba manual: `MCP_TRANSPORT=http EMAIL_USERS_FILE=/tmp/u.json MCP_USERS_KEY=… MCP_SIGNUP_CODE=curso MCP_PUBLIC_URL=http://127.0.0.1:8080 cpanel-mail-mcp`, abrir `/alta`, dar de alta una cuenta de prueba real y llamar a `list_folders` con la key.
- [ ] **Step 5: Commit** `feat: self-service signup page for course students`

---

### Tarea 5: Imagen Docker, compose y documentación para ruralgpt

**Files:**
- Modify: `Dockerfile`, `docker-compose.yml`, `.env.example`, `README.md`, `deploy/README.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: variables de las Tareas 2 y 4.
- Imagen: `EMAIL_USERS_FILE=/data/users.json`, `VOLUME /data`, `/data` creado con dueño `mcp` (uid 10001); sin `MCP_AUTH_MODE`.
- Compose: volumen nombrado `mail-mcp-data:/data`; env `MCP_USERS_KEY` y `MCP_PUBLIC_URL` obligatorias (`${VAR:?…}`), `MCP_SIGNUP_CODE` opcional, `EMAIL_SEND_CONFIRMATION_CODE` opcional; puerto `127.0.0.1:8080:8080` (detrás de nginx con HTTPS).
- README: sección nueva al principio, «ruralgpt.gal / Langdock», con: generar clave (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`), arrancar compose, compartir `https://<host>/alta` y el código, configurar la integración en Langdock (una vez, visible al workspace), cada alumno añade su conexión con su key, y activar «Request confirmation» en `send_email`, `reply_email`, `forward_email`, `send_invite`, `delete_email`, `delete_folder`. Quitar las secciones de n8n, CF Access y claude.ai Custom Connector. Advertencia RGPD: cuentas de prueba en el curso; si se pierde `MCP_USERS_KEY`, todos los alumnos deben repetir el alta.
- CHANGELOG: entrada `0.8.0-ruralgpt` con los cambios de las Tareas 1–4; `pyproject.toml` versión `0.8.0`.

- [ ] **Step 1:** `docker compose build && MCP_USERS_KEY=… MCP_PUBLIC_URL=http://127.0.0.1:8080 MCP_SIGNUP_CODE=x docker compose up -d` → `curl -s 127.0.0.1:8080/health` devuelve `ok` y `curl -s 127.0.0.1:8080/alta` devuelve el formulario, con el volumen vacío.
- [ ] **Step 2:** Alta de prueba desde el navegador; `docker compose restart`; la key sigue funcionando (el volumen persiste).
- [ ] **Step 3:** `.venv/bin/pytest` → PASS.
- [ ] **Step 4: Commit** `docs: ruralgpt deployment with Docker and Langdock setup`

---

## Fuera de alcance (v2)

- OAuth 2.0 en Langdock (opción B del documento).
- Baja autoservicio y rotación de `MCP_USERS_KEY` (MultiFernet). Por ahora: `admin remove-user` y repetir el alta.
- POP3.
- Despliegue concreto en el servidor de jamardo.xyz (nginx/certbot): se hace aparte con la imagen de la Tarea 5.
