"""Multi-user auth: `bearer token → Account` mapping.

The users file (path from `EMAIL_USERS_FILE`) is a JSON array:

    [
      {
        "token_sha256": "<hex sha256 of the bearer token>",
        "account": { ...accounts.json entry, with "password_enc" (Fernet,
                     key in MCP_USERS_KEY) instead of "password"... }
      },
      ...
    ]

When `EMAIL_USERS_FILE` is set the server runs in **multi-user mode**: the
token in `Authorization: Bearer …` identifies the caller and picks the
account. Callers cannot override the account by passing `params.account`.
Build entries with `make_entry`; see `vault` for the at-rest format.

The running server re-reads the file whenever it changes (`UsersStore`), so
`admin add-user` / `rotate-token` / `remove-user` take effect on the next
request without a restart.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import tempfile
import threading
from pathlib import Path

from cryptography.fernet import Fernet

from . import vault
from .accounts import Account, _from_dict

log = logging.getLogger("cpanel_mail_mcp.users")


def users_path() -> Path | None:
    p = os.environ.get("EMAIL_USERS_FILE")
    return Path(p) if p else None


def is_multi_user() -> bool:
    """True when `EMAIL_USERS_FILE` is set, even if the file doesn't exist yet
    (a fresh container volume): it then simply has no users."""
    return users_path() is not None


def make_entry(token: str, account: dict, f: Fernet) -> dict:
    """users.json entry for `account` (with a plaintext "password"): only the
    token's hash and the encrypted password are kept."""
    acct = {k: v for k, v in account.items() if k != "password"}
    acct["password_enc"] = vault.encrypt(f, account["password"])
    return {"token_sha256": vault.hash_token(token), "account": acct}


def load_users(path: Path | None = None, f: Fernet | None = None) -> dict[str, Account]:
    """Return `{sha256(token): Account}` for the configured (or given) users file."""
    p = path or users_path()
    if not p or not p.is_file():
        return {}
    data = json.loads(p.read_text() or "[]")
    if not isinstance(data, list):
        raise ValueError(f"{p} must contain a JSON array")
    f = f or vault.load_key()
    out: dict[str, Account] = {}
    for i, entry in enumerate(data):
        acct_raw = entry.get("account") or {}
        if "token" in entry or "password" in acct_raw:
            raise ValueError(f"{p}[{i}] is a plaintext entry; re-add it with `admin add-user`")
        h = entry.get("token_sha256")
        if not h or not acct_raw.get("password_enc"):
            raise ValueError(f"{p}[{i}] missing 'token_sha256' or 'account.password_enc'")
        if h in out:
            raise ValueError(f"{p}[{i}] duplicate token")
        try:
            password = vault.decrypt(f, acct_raw["password_enc"])
        except ValueError as e:
            raise ValueError(f"{p}[{i}]: {e}") from None
        d = {k: v for k, v in acct_raw.items() if k != "password_enc"}
        d["password"] = password
        out[h] = _from_dict(d)
    return out


def load_users_raw() -> list[dict]:
    p = users_path()
    if not p or not p.is_file():
        return []
    return json.loads(p.read_text() or "[]")


def save_users(users: list[dict]) -> None:
    """Atomically replace the users file. The temp file is created 0600 (never
    briefly world-readable) and keeps the previous file's owner, so a root
    admin editing it doesn't lock out the service user."""
    p = users_path()
    if not p:
        raise SystemExit(
            "EMAIL_USERS_FILE not set. "
            "Point it to a path like /etc/cpanel-mail-mcp/users.json first."
        )
    p.parent.mkdir(parents=True, exist_ok=True)
    prev = p.stat() if p.exists() else None
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(users, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        if prev is not None:
            try:
                os.chown(tmp, prev.st_uid, prev.st_gid)
            except PermissionError:
                pass
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


class UsersStore:
    """`{sha256(token): Account}` view of the users file, reloaded when it changes.

    Checked with one `stat()` per request. If the file becomes unreadable or
    invalid, the last good map is kept and the error is logged; if it is
    deleted, every token is revoked.
    """

    def __init__(self, path: Path, f: Fernet | None = None) -> None:
        self.path = path
        self._fernet = f or vault.load_key()
        self._lock = threading.Lock()
        self._sig: tuple | None = None
        self._users: dict[str, Account] = {}
        self.get()

    def get(self) -> dict[str, Account]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            if self._users:
                log.warning("users file %s disappeared — all tokens revoked", self.path)
            self._users, self._sig = {}, None
            return self._users
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        if sig == self._sig:
            return self._users
        with self._lock:
            if sig != self._sig:
                try:
                    self._users = load_users(self.path, self._fernet)
                    log.info("loaded %d user(s) from %s", len(self._users), self.path)
                except Exception as e:
                    log.error("cannot reload %s (keeping previous users): %s", self.path, e)
                self._sig = sig
        return self._users


_upsert_lock = threading.Lock()


def upsert_user(entry: dict) -> bool:
    """Add `entry`, replacing any entry for the same mailbox (case-insensitive).
    Returns True when an existing entry was replaced (its token is revoked)."""
    user = entry["account"]["user"].lower()
    with _upsert_lock:
        all_users = load_users_raw()
        kept = [u for u in all_users if u.get("account", {}).get("user", "").lower() != user]
        save_users(kept + [entry])
        return len(kept) != len(all_users)


def new_token() -> str:
    return secrets.token_urlsafe(36)
