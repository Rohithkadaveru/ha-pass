"""Tests for admin API endpoints: login, logout, token CRUD.

These are integration tests exercising real FastAPI routing, real bcrypt
password verification, real SQLite database, and real Pydantic validation.
Only ha_client is mocked (external dependency).
"""
import time

import pytest

from app import database as db
from app.auth import SESSION_COOKIE
from app.models import NEVER_EXPIRES_SECONDS


# ---------------------------------------------------------------------------
# Login — real bcrypt, real DB session creation
# ---------------------------------------------------------------------------

async def test_login_success_creates_session_in_db(client, mock_ha_client, test_db):
    """Successful login sets a cookie AND persists the session in the real DB."""
    resp = await client.post(
        "/admin/login",
        json={"username": "testadmin", "password": "testpassword123"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # Verify cookie is set
    session_id = resp.cookies.get(SESSION_COOKIE)
    assert session_id is not None

    # Verify the session actually exists in the database
    row = await db.get_admin_session(session_id)
    assert row is not None
    assert row["id"] == session_id


async def test_login_wrong_password(client, mock_ha_client, test_db):
    resp = await client.post(
        "/admin/login",
        json={"username": "testadmin", "password": "wrongpassword"},
    )
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


async def test_login_wrong_username(client, mock_ha_client, test_db):
    resp = await client.post(
        "/admin/login",
        json={"username": "wronguser", "password": "testpassword123"},
    )
    assert resp.status_code == 401


async def test_login_rate_limiting_isolated(client, mock_ha_client, test_db):
    """After exactly 5 failed attempts from the same IP, the 6th is rate-limited.

    The _reset_login_limiter autouse fixture ensures this test starts with
    a clean rate limiter — no pollution from other tests.
    """
    for i in range(5):
        resp = await client.post(
            "/admin/login",
            json={"username": "testadmin", "password": "wrong"},
        )
        assert resp.status_code == 401, f"Attempt {i+1} should be 401, not rate-limited"

    resp = await client.post(
        "/admin/login",
        json={"username": "testadmin", "password": "wrong"},
    )
    assert resp.status_code == 429


async def test_login_rate_limiting_blocks_valid_credentials_too(client, mock_ha_client, test_db):
    """Once rate-limited, even correct credentials are rejected."""
    for _ in range(5):
        await client.post(
            "/admin/login",
            json={"username": "testadmin", "password": "wrong"},
        )
    # Now try with correct credentials — still rate-limited
    resp = await client.post(
        "/admin/login",
        json={"username": "testadmin", "password": "testpassword123"},
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Logout — real DB session deletion
# ---------------------------------------------------------------------------

async def test_logout_deletes_session_from_db(client, admin_session, mock_ha_client):
    """Logout removes the session from the DB, not just the cookie."""
    session_id = admin_session[SESSION_COOKIE]
    resp = await client.post("/admin/logout", cookies=admin_session)
    assert resp.status_code == 200

    # Session should be gone from the database
    row = await db.get_admin_session(session_id)
    assert row is None


# ---------------------------------------------------------------------------
# Token CRUD — real DB, real Pydantic validation
# ---------------------------------------------------------------------------

async def test_create_token_persists_in_db(client, admin_session, mock_ha_client):
    """Token creation returns 201 AND the token is queryable from the DB."""
    resp = await client.post(
        "/admin/tokens",
        json={
            "label": "Guest WiFi",
            "entity_ids": ["light.a", "switch.b"],
            "expires_in_seconds": 3600,
        },
        cookies=admin_session,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["label"] == "Guest WiFi"
    assert data["entity_count"] == 2

    # Verify in the actual database
    row = await db.get_token_by_id(data["id"])
    assert row is not None
    assert row["label"] == "Guest WiFi"
    entities = await db.get_token_entities(data["id"])
    assert set(entities) == {"light.a", "switch.b"}


async def test_create_token_auto_slug_is_random(client, admin_session, mock_ha_client):
    """When no slug is provided, a random 32-char hex slug is generated."""
    resp = await client.post(
        "/admin/tokens",
        json={
            "label": "No Slug",
            "entity_ids": ["light.a"],
            "expires_in_seconds": 3600,
        },
        cookies=admin_session,
    )
    assert resp.status_code == 201
    slug = resp.json()["slug"]
    assert len(slug) == 32

    # Verify it's queryable by slug in the DB
    row = await db.get_token_by_slug(slug)
    assert row is not None


async def test_create_token_never_expires(client, admin_session, mock_ha_client):
    resp = await client.post(
        "/admin/tokens",
        json={
            "label": "Forever",
            "entity_ids": ["light.a"],
            "expires_in_seconds": NEVER_EXPIRES_SECONDS,
        },
        cookies=admin_session,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["expires_at"] == NEVER_EXPIRES_SECONDS

    # Verify in DB
    row = await db.get_token_by_id(data["id"])
    assert row["expires_at"] == NEVER_EXPIRES_SECONDS


async def test_create_token_duplicate_slug_409(client, admin_session, mock_ha_client):
    """Duplicate slugs are caught and return 409 with a meaningful message."""
    await client.post(
        "/admin/tokens",
        json={
            "label": "First",
            "slug": "unique-slug",
            "entity_ids": ["light.a"],
            "expires_in_seconds": 3600,
        },
        cookies=admin_session,
    )
    resp = await client.post(
        "/admin/tokens",
        json={
            "label": "Second",
            "slug": "unique-slug",
            "entity_ids": ["light.a"],
            "expires_in_seconds": 3600,
        },
        cookies=admin_session,
    )
    assert resp.status_code == 409
    assert "unique-slug" in resp.json()["detail"]


async def test_create_token_invalid_cidr_422(client, admin_session, mock_ha_client):
    resp = await client.post(
        "/admin/tokens",
        json={
            "label": "Bad CIDR",
            "entity_ids": ["light.a"],
            "expires_in_seconds": 3600,
            "ip_allowlist": ["not-a-cidr"],
        },
        cookies=admin_session,
    )
    assert resp.status_code == 422
    assert "CIDR" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Token listing and detail — real DB queries
# ---------------------------------------------------------------------------

async def test_list_tokens_returns_all_with_entity_counts(client, admin_session, mock_ha_client):
    """Token listing includes entity_count computed via SQL JOIN."""
    # Create two tokens with different entity counts
    await client.post(
        "/admin/tokens",
        json={"label": "One", "slug": "one", "entity_ids": ["light.a"], "expires_in_seconds": 3600},
        cookies=admin_session,
    )
    await client.post(
        "/admin/tokens",
        json={"label": "Three", "slug": "three", "entity_ids": ["light.a", "switch.b", "fan.c"], "expires_in_seconds": 3600},
        cookies=admin_session,
    )
    resp = await client.get("/admin/tokens", cookies=admin_session)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    counts = {t["slug"]: t["entity_count"] for t in data}
    assert counts["one"] == 1
    assert counts["three"] == 3


async def test_get_token_detail_includes_entities(client, admin_session, sample_token, mock_ha_client):
    """Token detail endpoint returns the actual entity list from the DB."""
    resp = await client.get(
        f"/admin/tokens/{sample_token['id']}", cookies=admin_session
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_ids"] == ["light.living_room"]
    assert data["slug"] == "test-token"
    assert data["label"] == "Test Token"


async def test_get_nonexistent_token_404(client, admin_session, mock_ha_client):
    resp = await client.get(
        "/admin/tokens/nonexistent-id", cookies=admin_session
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Token updates — real DB mutations + side effects
# ---------------------------------------------------------------------------

async def test_update_token_entities_persists_and_invalidates_cache(
    client, admin_session, sample_token, mock_ha_client
):
    """Updating entities changes the DB AND calls invalidate_entity_cache."""
    resp = await client.patch(
        f"/admin/tokens/{sample_token['id']}/entities",
        json={"entity_ids": ["switch.a", "fan.b"]},
        cookies=admin_session,
    )
    assert resp.status_code == 200
    assert set(resp.json()["entity_ids"]) == {"switch.a", "fan.b"}

    # Verify in DB directly
    entities = await db.get_token_entities(sample_token["id"])
    assert set(entities) == {"switch.a", "fan.b"}

    # Verify the HA entity cache was invalidated
    mock_ha_client["invalidate_entity_cache"].assert_called_once_with(sample_token["id"])


async def test_update_revoked_token_entities_rejected(client, admin_session, sample_token, mock_ha_client):
    """Cannot modify entities on a revoked token — business rule enforced."""
    await db.revoke_token(sample_token["id"])
    resp = await client.patch(
        f"/admin/tokens/{sample_token['id']}/entities",
        json={"entity_ids": ["switch.a"]},
        cookies=admin_session,
    )
    assert resp.status_code == 400
    assert "revoked" in resp.json()["detail"].lower()


async def test_update_token_expiry_persists(client, admin_session, sample_token, mock_ha_client):
    """Updating expiry changes the actual expires_at value in the DB."""
    resp = await client.patch(
        f"/admin/tokens/{sample_token['id']}/expiry",
        json={"expires_in_seconds": 7200},
        cookies=admin_session,
    )
    assert resp.status_code == 200
    new_expires = resp.json()["expires_at"]
    now = int(time.time())
    assert now + 7000 < new_expires < now + 7400

    # Verify in DB
    row = await db.get_token_by_id(sample_token["id"])
    assert row["expires_at"] == new_expires


async def test_update_revoked_token_expiry_unrevokes(client, admin_session, sample_token, mock_ha_client):
    """Extending a revoked token's expiry un-revokes it (admin is renewing)."""
    await db.revoke_token(sample_token["id"])
    resp = await client.patch(
        f"/admin/tokens/{sample_token['id']}/expiry",
        json={"expires_in_seconds": 7200},
        cookies=admin_session,
    )
    assert resp.status_code == 200

    # Token should no longer be revoked
    row = await db.get_token_by_id(sample_token["id"])
    assert row["revoked"] == 0


# ---------------------------------------------------------------------------
# Token deletion — real DB mutations + SSE notification
# ---------------------------------------------------------------------------

async def test_soft_revoke_sets_flag_and_notifies_sse(client, admin_session, sample_token, mock_ha_client):
    """Soft delete sets revoked=1 in DB and broadcasts token_expired via SSE."""
    resp = await client.delete(
        f"/admin/tokens/{sample_token['id']}", cookies=admin_session
    )
    assert resp.status_code == 200

    # Verify in DB
    row = await db.get_token_by_id(sample_token["id"])
    assert row["revoked"] == 1

    # Verify SSE broadcast was triggered
    mock_ha_client["broadcast_token_expired"].assert_called_once_with(sample_token["id"])


async def test_hard_delete_removes_from_db(client, admin_session, sample_token, mock_ha_client):
    """Hard delete removes the token row entirely."""
    resp = await client.delete(
        f"/admin/tokens/{sample_token['id']}/hard", cookies=admin_session
    )
    assert resp.status_code == 200
    assert await db.get_token_by_id(sample_token["id"]) is None


async def test_hard_delete_cascades_entities(client, admin_session, sample_token, mock_ha_client):
    """Hard delete also removes associated token_entities rows (FK CASCADE)."""
    tid = sample_token["id"]
    # Verify entities exist before delete
    assert len(await db.get_token_entities(tid)) == 1

    await client.delete(f"/admin/tokens/{tid}/hard", cookies=admin_session)

    assert await db.get_token_entities(tid) == []


async def test_hard_delete_notifies_sse(client, admin_session, sample_token, mock_ha_client):
    """Hard delete also broadcasts token_expired so SSE clients disconnect."""
    await client.delete(
        f"/admin/tokens/{sample_token['id']}/hard", cookies=admin_session
    )
    mock_ha_client["broadcast_token_expired"].assert_called_once_with(sample_token["id"])
