"""End-to-end HTTP smoke: /health, 401 with WWW-Authenticate, no OAuth endpoints.

Uses a real uvicorn server on a private port + urllib requests. No mocks of
the network layer.
"""
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from cpanel_mail_mcp import users as users_mod, vault


ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_server(tmp_path):
    port = _free_port()
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps([users_mod.make_entry("test-token-1234567890", {
        "name": "x", "user": "u@v.com", "password": "p",
        "smtp_host": "s", "imap_host": "i",
    }, vault.load_key())]))
    env = {
        **os.environ,
        "EMAIL_USERS_FILE": str(users_file),
        "MCP_TRANSPORT": "http",
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(port),
        "MCP_ALLOWED_HOSTS": "127.0.0.1,localhost",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cpanel_mail_mcp"],
        env=env, cwd=str(ROOT),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(30):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5).read()
                break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("server never came up")
        yield port
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()


def test_health(running_server):
    port = running_server
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/health").read()
    assert body == b"ok"




def test_mcp_without_auth_returns_401(running_server):
    port = running_server
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
        data=b"{}",
    )
    try:
        urllib.request.urlopen(req)
        pytest.fail("expected 401")
    except urllib.error.HTTPError as e:
        assert e.code == 401
        assert e.headers.get("www-authenticate", "") == 'Bearer realm="mcp"'


def _status(url: str, method: str = "GET") -> int:
    try:
        return urllib.request.urlopen(urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)).status
    except urllib.error.HTTPError as e:
        return e.code


def test_oauth_endpoints_are_gone(running_server):
    port = running_server
    assert _status(f"http://127.0.0.1:{port}/.well-known/oauth-protected-resource") == 401
    assert _status(f"http://127.0.0.1:{port}/register", "POST") == 401
