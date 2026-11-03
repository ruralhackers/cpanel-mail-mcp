"""Check a mailbox before registering it, and detect its special folders.

Used by the signup page: a student's IMAP (and optionally SMTP) login is
tried once, and the Sent / Drafts / Trash folders are picked from the
server's own listing so the account works without hand-tuned folder names.
"""
from __future__ import annotations

import imaplib
import smtplib
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Literal

from . import imap_ops, smtp_ops
from .accounts import Account

Protocol = Literal["imap", "smtp"]

_SENT_CANDIDATES = (
    "INBOX.Sent", "Sent", "Sent Items", "INBOX.Sent Items", "Sent Messages",
    "[Gmail]/Sent Mail", "Enviados", "INBOX.Enviados", "Elementos enviados",
)
_DRAFTS_CANDIDATES = (
    "INBOX.Drafts", "Drafts", "[Gmail]/Drafts", "Borradores", "INBOX.Borradores",
)
# These servers already file what is sent through SMTP; an IMAP APPEND would duplicate it.
_AUTO_SAVES_SENT = ("imap.gmail.com", "outlook.office365.com")


class MailboxRejected(Exception):
    def __init__(self, protocol: Protocol, detail: str = "") -> None:
        super().__init__(f"{protocol} login rejected" + (f": {detail}" if detail else ""))
        self.protocol = protocol


class MailServerUnreachable(Exception):
    def __init__(self, protocol: Protocol, detail: str = "") -> None:
        super().__init__(f"{protocol} server unreachable" + (f": {detail}" if detail else ""))
        self.protocol = protocol


class Throttled(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"too many failed attempts; retry in {retry_after}s")
        self.retry_after = retry_after


@dataclass(frozen=True)
class MailboxInfo:
    sent_folder: str
    drafts_folder: str
    trash_folder: str | None
    save_to_sent: bool


def _pick(folders: list[dict], flag: str, candidates: tuple[str, ...]) -> str | None:
    for f in folders:
        if flag in f["flags"].lower().split():
            return f["name"]
    by_lower = {f["name"].lower(): f["name"] for f in folders}
    for c in candidates:
        if c.lower() in by_lower:
            return by_lower[c.lower()]
    return None


def verify_mailbox(acct: Account, *, check_smtp: bool) -> MailboxInfo:
    """Log in over IMAP (and SMTP if asked) and detect folders. Blocking."""
    try:
        m = imap_ops._connect(acct)
    except imaplib.IMAP4.error as e:
        raise MailboxRejected("imap", str(e)) from e
    except OSError as e:
        raise MailServerUnreachable("imap", str(e)) from e
    try:
        folders = imap_ops._list(m)
    finally:
        try:
            m.logout()
        except Exception:
            pass

    if check_smtp:
        try:
            s = smtp_ops._connect(acct)
        except smtplib.SMTPAuthenticationError as e:
            raise MailboxRejected("smtp", str(e)) from e
        except (OSError, smtplib.SMTPException) as e:
            raise MailServerUnreachable("smtp", str(e)) from e
        try:
            s.quit()
        except Exception:
            pass

    sent = _pick(folders, "\\sent", _SENT_CANDIDATES)
    drafts = _pick(folders, "\\drafts", _DRAFTS_CANDIDATES)
    trash = _pick(folders, "\\trash", imap_ops._TRASH_CANDIDATES)
    auto_saves = acct.imap_host.lower() in _AUTO_SAVES_SENT
    return MailboxInfo(
        sent_folder=sent or "Sent",
        drafts_folder=drafts or "Drafts",
        trash_folder=trash,
        save_to_sent=bool(sent) and not auto_saves,
    )


class LoginThrottle:
    """Sliding-window cap on failed attempts, per user and overall."""

    def __init__(self, max_per_user: int = 5, max_global: int = 50, window_seconds: int = 900,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_user = max_per_user
        self.max_global = max_global
        self.window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._user: dict[str, deque[float]] = {}
        self._global: deque[float] = deque()

    def _prune(self, q: deque[float], now: float) -> None:
        while q and q[0] <= now - self.window:
            q.popleft()

    def _retry_after(self, q: deque[float], now: float) -> int:
        return max(1, int(q[0] + self.window - now))

    def check(self, user: str) -> None:
        now = self._clock()
        with self._lock:
            uq = self._user.get(user)
            if uq is not None:
                self._prune(uq, now)
                if len(uq) >= self.max_user:
                    raise Throttled(self._retry_after(uq, now))
            self._prune(self._global, now)
            if len(self._global) >= self.max_global:
                raise Throttled(self._retry_after(self._global, now))

    def failure(self, user: str) -> None:
        now = self._clock()
        with self._lock:
            self._user.setdefault(user, deque()).append(now)
            self._global.append(now)

    def success(self, user: str) -> None:
        with self._lock:
            self._user.pop(user, None)
