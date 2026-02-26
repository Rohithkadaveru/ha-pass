"""Tests for admin authentication: bcrypt verification and session-based access control."""
import pytest

from app.auth import SESSION_COOKIE, verify_password
from app import database as db


# ---------------------------------------------------------------------------
# Password verification (real bcrypt, no mocks)
# ---------------------------------------------------------------------------

async def test_verify_correct_password():
    """Real bcrypt hash comparison succeeds with the configured password."""
    assert await verify_password("testpassword123") is True


async def test_verify_wrong_password():
    assert await verify_password("wrongpassword") is False


async def test_verify_empty_password():
    assert await verify_password("") is False


async def test_verify_similar_password():
    """Passwords differing by one character are rejected."""
    assert await verify_password("testpassword12") is False
    assert await verify_password("testpassword1234") is False


# ---------------------------------------------------------------------------
# Session-based access control (real DB, real routing)
# ---------------------------------------------------------------------------

async def test_require_admin_no_cookie_returns_401(client, mock_ha_client):
    """No session cookie → 401 with proper error detail."""
    resp = await client.get("/admin/tokens")
    assert resp.status_code == 401
    assert "Not authenticated" in resp.json()["detail"]


async def test_require_admin_invalid_cookie_returns_401(client, mock_ha_client):
    """Bogus session ID → 401 because it doesn't exist in the DB."""
    resp = await client.get(
        "/admin/tokens",
        cookies={SESSION_COOKIE: "nonexistent-session-id"},
    )
    assert resp.status_code == 401
    assert "Session expired" in resp.json()["detail"]


async def test_require_admin_valid_session_grants_access(client, admin_session, mock_ha_client):
    """A session that exists in the DB and isn't expired grants access."""
    resp = await client.get("/admin/tokens", cookies=admin_session)
    assert resp.status_code == 200


async def test_require_admin_expired_session_returns_401(client, mock_ha_client, test_db):
    """A session whose expires_at is in the past is rejected."""
    import time

    conn = await db.get_db()
    now = int(time.time())
    await conn.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        ("expired-sess", now - 100, now - 1),
    )
    await conn.commit()

    resp = await client.get(
        "/admin/tokens",
        cookies={SESSION_COOKIE: "expired-sess"},
    )
    assert resp.status_code == 401


async def test_deleted_session_no_longer_grants_access(client, mock_ha_client, test_db):
    """After deleting a session from the DB, the same cookie is rejected."""
    session_id = await db.create_admin_session(ttl_seconds=86400)
    # Verify it works first
    resp = await client.get("/admin/tokens", cookies={SESSION_COOKIE: session_id})
    assert resp.status_code == 200

    # Delete and retry
    await db.delete_admin_session(session_id)
    resp = await client.get("/admin/tokens", cookies={SESSION_COOKIE: session_id})
    assert resp.status_code == 401
