"""vault: Fernet key loading, password encryption and token hashing."""
import hashlib

import pytest

from cpanel_mail_mcp import vault


def test_roundtrip_and_hash():
    f = vault.load_key()
    assert vault.decrypt(f, vault.encrypt(f, "pä&ss= +%")) == "pä&ss= +%"
    assert vault.hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_ciphertext_is_not_plaintext():
    f = vault.load_key()
    assert "s3cr3t" not in vault.encrypt(f, "s3cr3t")


def test_missing_key_exits(monkeypatch):
    monkeypatch.delenv("MCP_USERS_KEY")
    with pytest.raises(SystemExit, match="MCP_USERS_KEY"):
        vault.load_key()


def test_bad_key_exits(monkeypatch):
    monkeypatch.setenv("MCP_USERS_KEY", "nope")
    with pytest.raises(SystemExit, match="MCP_USERS_KEY"):
        vault.load_key()


def test_decrypt_with_wrong_key_raises_value_error():
    from cryptography.fernet import Fernet
    blob = vault.encrypt(vault.load_key(), "x")
    with pytest.raises(ValueError):
        vault.decrypt(Fernet(Fernet.generate_key()), blob)
