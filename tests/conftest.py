import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def users_key(monkeypatch):
    """Every test gets a fresh Fernet key; subprocess servers inherit it."""
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("MCP_USERS_KEY", key)
    return key
