"""users.json load/save + admin CLI subcommands."""
import json
import os

import pytest

from cpanel_mail_mcp import admin, users as users_mod, vault


@pytest.fixture
def users_file(tmp_path, monkeypatch):
    p = tmp_path / "users.json"
    p.write_text("[]")
    monkeypatch.setenv("EMAIL_USERS_FILE", str(p))
    return p


def _run(argv):
    return admin.main(argv)


def test_is_multi_user(users_file):
    assert users_mod.is_multi_user()


def test_add_user_writes_token(users_file, capsys):
    rc = _run(["add-user", "--email", "juan@dom.com", "--password", "pw",
               "--host", "mail.dom.com"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "juan@dom.com" in out
    assert "bearer token" in out.lower()
    data = json.loads(users_file.read_text())
    assert len(data) == 1
    assert data[0]["account"]["user"] == "juan@dom.com"
    token = next(line.strip() for line in out.splitlines() if len(line.strip()) > 40 and " " not in line.strip())
    assert data[0]["token_sha256"] == vault.hash_token(token)
    assert vault.hash_token(token) in users_mod.load_users()


def test_add_user_duplicate_fails(users_file):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    rc = _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    assert rc == 1


def test_list_users(users_file, capsys):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    _run(["add-user", "--email", "b@x.com", "--password", "p", "--host", "h"])
    capsys.readouterr()  # drain
    rc = _run(["list-users"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "a@x.com" in out
    assert "b@x.com" in out


def test_rotate_token(users_file, capsys):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    old = json.loads(users_file.read_text())[0]["token_sha256"]
    capsys.readouterr()
    rc = _run(["rotate-token", "--email", "a@x.com"])
    out = capsys.readouterr().out
    new = json.loads(users_file.read_text())[0]["token_sha256"]
    assert rc == 0
    assert old != new
    token = next(line.strip() for line in out.splitlines() if len(line.strip()) > 40 and " " not in line.strip())
    assert vault.hash_token(token) == new


def test_remove_user(users_file):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    _run(["add-user", "--email", "b@x.com", "--password", "p", "--host", "h"])
    _run(["remove-user", "--email", "a@x.com"])
    data = json.loads(users_file.read_text())
    assert [e["account"]["user"] for e in data] == ["b@x.com"]




def test_load_users_matches_json(users_file):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    loaded = users_mod.load_users()
    assert len(loaded) == 1
    acct = next(iter(loaded.values()))
    assert acct.user == "a@x.com"


def test_file_has_no_plaintext(users_file, capsys):
    _run(["add-user", "--email", "j@d.com", "--password", "s3cr3t-pw", "--host", "h"])
    raw = users_file.read_text()
    assert "s3cr3t-pw" not in raw
    assert '"token"' not in raw and '"password"' not in raw
    assert "token_sha256" in raw and "password_enc" in raw
    acct = next(iter(users_mod.load_users().values()))
    assert acct.password == "s3cr3t-pw"


def test_list_users_shows_hash_prefix_only(users_file, capsys):
    _run(["add-user", "--email", "a@x.com", "--password", "p", "--host", "h"])
    h = json.loads(users_file.read_text())[0]["token_sha256"]
    capsys.readouterr()
    _run(["list-users"])
    out = capsys.readouterr().out
    assert h[:8] in out and h not in out


def test_plaintext_entry_rejected(tmp_path):
    p = tmp_path / "u.json"
    p.write_text(json.dumps([{"token": "t" * 30,
                              "account": {"user": "a@x", "password": "p", "host": "h"}}]))
    with pytest.raises(ValueError, match="plaintext"):
        users_mod.load_users(p)


def test_is_multi_user_without_file(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAIL_USERS_FILE", str(tmp_path / "missing.json"))
    assert users_mod.is_multi_user()
    assert users_mod.load_users() == {}
