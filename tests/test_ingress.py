"""Tests for ingress detection and ingress-based auth bypass.

These cover the new ingress feature: header spoofing prevention,
admin auth bypass for HA sidebar, login disabled in add-on mode,
and logout sentinel safety.
"""
from unittest.mock import patch

import httpx

import app.ingress
from app import database as db


# ---------------------------------------------------------------------------
# Security: header spoofing prevention
# ---------------------------------------------------------------------------

def test_ingress_header_ignored_without_supervisor_token():
    """Without SUPERVISOR_TOKEN, X-Ingress-Path is untrusted — blocks spoofing."""
    from unittest.mock import MagicMock
    req = MagicMock()
    req.headers = {"X-Ingress-Path": "/api/hassio_ingress/spoofed"}
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", None):
        assert app.ingress.get_ingress_path(req) == ""


def test_ingress_header_requires_supervisor_transport_peer():
    """A client that can set the header cannot impersonate Supervisor ingress."""
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"X-Ingress-Path": "/api/hassio_ingress/forged"}
    req.client.host = "192.0.2.10"
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"):
        assert app.ingress.get_ingress_path(req) == ""


def test_ingress_header_accepts_documented_supervisor_peer():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"X-Ingress-Path": "/api/hassio_ingress/valid"}
    req.client.host = "172.30.32.2"
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"):
        assert app.ingress.get_ingress_path(req) == "/api/hassio_ingress/valid"


def test_standalone_client_ip_preserves_reverse_proxy_header():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"X-Forwarded-For": "198.51.100.7, 127.0.0.1"}
    req.client.host = "127.0.0.1"
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", None):
        assert app.ingress.client_ip(req) == "198.51.100.7"


def test_addon_client_ip_ignores_forwarded_header_from_direct_peer():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {"X-Forwarded-For": "198.51.100.7"}
    req.client.host = "192.0.2.10"
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"):
        assert app.ingress.client_ip(req) == "192.0.2.10"


def test_ingress_client_ip_uses_forwarded_header_after_peer_check():
    from unittest.mock import MagicMock

    req = MagicMock()
    req.headers = {
        "X-Ingress-Path": "/api/hassio_ingress/valid",
        "X-Forwarded-For": "198.51.100.7, 172.30.32.2",
    }
    req.client.host = "172.30.32.2"
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"):
        assert app.ingress.client_ip(req) == "198.51.100.7"


# ---------------------------------------------------------------------------
# Integration: ingress auth bypass
# ---------------------------------------------------------------------------

async def test_ingress_bypass_grants_admin_access(client, mock_ha_client, test_db):
    """Ingress requests skip session auth — admin endpoints accessible without cookie."""
    with patch("app.auth.is_ingress_request", return_value=True):
        resp = await client.get("/admin/tokens")
    assert resp.status_code == 200


async def test_forged_ingress_header_does_not_grant_admin_access(mock_ha_client, test_db):
    """A direct add-on request with a forged ingress header remains unauthorized."""
    from app.config import settings
    from main import app as fastapi_app

    transport = httpx.ASGITransport(app=fastapi_app, client=("192.0.2.10", 12345))
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"), \
         patch.object(settings, "supervisor_token", "synthetic-token"):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            resp = await c.get(
                "/admin/tokens",
                headers={"X-Ingress-Path": "/api/hassio_ingress/forged"},
            )
    assert resp.status_code == 401


async def test_supervisor_peer_grants_admin_access(mock_ha_client, test_db):
    """A request from the documented Supervisor peer can use ingress auth."""
    from app.config import settings
    from main import app as fastapi_app

    transport = httpx.ASGITransport(app=fastapi_app, client=("172.30.32.2", 12345))
    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"), \
         patch.object(settings, "supervisor_token", "synthetic-token"):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            resp = await c.get(
                "/admin/tokens",
                headers={"X-Ingress-Path": "/api/hassio_ingress/valid"},
            )
    assert resp.status_code == 200


async def test_configured_addon_password_login_remains_available(client, mock_ha_client, test_db):
    """Configured add-on credentials continue to support direct-port login."""
    from app.config import settings

    with patch.object(app.ingress, "_SUPERVISOR_TOKEN", "synthetic-token"), \
         patch.object(settings, "supervisor_token", "synthetic-token"):
        resp = await client.post(
            "/admin/login",
            json={"username": "testadmin", "password": "testpassword123"},
        )
        assert resp.status_code == 200
        follow_up = await client.get("/admin/tokens")
    assert follow_up.status_code == 200


async def test_login_returns_403_when_no_password(client, mock_ha_client, test_db):
    """In add-on mode (empty password), login endpoint returns 403."""
    from app.config import settings
    with patch.object(settings, "admin_password", ""):
        resp = await client.post(
            "/admin/login",
            json={"username": "testadmin", "password": "anything"},
        )
    assert resp.status_code == 403
    assert "Login disabled" in resp.json()["detail"]


async def test_ingress_logout_does_not_delete_real_sessions(client, mock_ha_client, test_db):
    """Ingress logout returns ok without accidentally wiping a real session."""
    session_id = await db.create_admin_session(ttl_seconds=86400)
    with patch("app.auth.is_ingress_request", return_value=True):
        resp = await client.post("/admin/logout")
    assert resp.status_code == 200
    row = await db.get_admin_session(session_id)
    assert row is not None
