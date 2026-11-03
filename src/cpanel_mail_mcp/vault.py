"""Secrets at rest for the multi-user users.json.

Mailbox passwords are stored Fernet-encrypted with the key in
`MCP_USERS_KEY`; bearer tokens are stored only as their SHA-256, so a copy
of users.json alone neither reveals passwords nor lets anyone impersonate a
user. Generate a key with:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Losing the key means every user has to register again.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

KEY_ENV = "MCP_USERS_KEY"


def load_key() -> Fernet:
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        raise SystemExit(
            f"{KEY_ENV} is not set. Generate one with: python -c \"from cryptography.fernet "
            f"import Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        return Fernet(raw.encode())
    except (ValueError, TypeError):
        raise SystemExit(f"{KEY_ENV} is not a valid Fernet key (urlsafe base64, 32 bytes).") from None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt(f: Fernet, plaintext: str) -> str:
    return f.encrypt(plaintext.encode()).decode("ascii")


def decrypt(f: Fernet, token: str) -> str:
    try:
        return f.decrypt(token.encode("ascii")).decode()
    except (InvalidToken, ValueError, UnicodeError) as e:
        raise ValueError("cannot decrypt password (wrong MCP_USERS_KEY?)") from e
