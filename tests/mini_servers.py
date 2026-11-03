"""Tiny plaintext IMAP / SMTP servers on localhost, so login code runs through
the real imaplib / smtplib (their ASCII handling is what we test)."""
from __future__ import annotations

import base64
import socket
import threading


class _Server:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.seen: list[bytes] = []
        self.auth: tuple[str, str] | None = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        conn, _ = self.sock.accept()
        with conn, conn.makefile("rwb") as f:
            self.session(f)

    def close(self) -> None:
        self.sock.close()


def _plain(blob: bytes) -> tuple[str, str]:
    _, user, pw = base64.b64decode(blob).split(b"\0")
    return user.decode(), pw.decode()


class MiniIMAP(_Server):
    def session(self, f) -> None:
        f.write(b"* OK ready\r\n"); f.flush()
        while line := f.readline():
            self.seen.append(line)
            tag, cmd, *rest = line.rstrip(b"\r\n").split(b" ", 2)
            cmd = cmd.upper()
            if cmd == b"CAPABILITY":
                f.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n" + tag + b" OK done\r\n")
            elif cmd == b"AUTHENTICATE":
                f.write(b"+ \r\n"); f.flush()
                self.auth = _plain(f.readline().strip())
                f.write(tag + b" OK logged in\r\n")
            elif cmd == b"LOGIN":
                u, p = rest[0].split(b" ", 1)
                self.auth = (u.strip(b'"').decode(), p.strip(b'"').decode())
                f.write(tag + b" OK logged in\r\n")
            elif cmd == b"LOGOUT":
                f.write(b"* BYE\r\n" + tag + b" OK bye\r\n"); f.flush()
                return
            else:
                f.write(tag + b" BAD unknown\r\n")
            f.flush()


class MiniSMTP(_Server):
    def session(self, f) -> None:
        f.write(b"220 ready\r\n"); f.flush()
        while line := f.readline():
            self.seen.append(line)
            cmd = line.strip().upper()
            if cmd.startswith((b"EHLO", b"HELO")):
                f.write(b"250-hi\r\n250 AUTH PLAIN LOGIN\r\n")
            elif cmd.startswith(b"AUTH PLAIN"):
                self.auth = _plain(line.strip().split(b" ")[2])
                f.write(b"235 ok\r\n")
            elif cmd == b"QUIT":
                f.write(b"221 bye\r\n"); f.flush()
                return
            else:
                f.write(b"502 no\r\n")
            f.flush()
