"""Tests for database CRUD operations."""
import time

import pytest

from app import database as db
from app.models import NEVER_EXPIRES_SECONDS


# ---------------------------------------------------------------------------
# Admin sessions
# ---------------------------------------------------------------------------

async def test_create_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    assert len(session_id) == 64  # two uuid4.hex concatenated


async def test_get_valid_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    row = await db.get_admin_session(session_id)
    assert row is not None
    assert row["id"] == session_id


async def test_get_expired_admin_session_returns_none(test_db):
    session_id = await db.create_admin_session(ttl_seconds=0)
    # Expiry is now + 0 = now, and the query checks expires_at > now
    # So with ttl=0, it may or may not be expired depending on timing.
    # Use ttl=-1 via direct insert to guarantee expiry.
    conn = await db.get_db()
    now = int(time.time())
    await conn.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        ("expired-session", now - 100, now - 1),
    )
    await conn.commit()
    row = await db.get_admin_session("expired-session")
    assert row is None


async def test_delete_admin_session(test_db):
    session_id = await db.create_admin_session(ttl_seconds=3600)
    await db.delete_admin_session(session_id)
    row = await db.get_admin_session(session_id)
    assert row is None


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

async def test_create_token(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test",
        slug="test-slug",
        entity_ids=["light.a"],
        expires_at=now + 3600,
        ip_allowlist=None,
    )
    assert token["slug"] == "test-slug"
    assert token["label"] == "Test"
    assert token["revoked"] == 0


async def test_get_token_by_slug(test_db):
    now = int(time.time())
    await db.create_token(
        label="Test", slug="by-slug", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    row = await db.get_token_by_slug("by-slug")
    assert row is not None
    assert row["slug"] == "by-slug"


async def test_get_token_by_id(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="by-id", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    row = await db.get_token_by_id(token["id"])
    assert row is not None
    assert row["id"] == token["id"]


async def test_list_tokens_with_entity_count(test_db):
    now = int(time.time())
    await db.create_token(
        label="Multi", slug="multi", entity_ids=["light.a", "switch.b", "fan.c"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    rows = await db.list_tokens()
    assert len(rows) == 1
    assert rows[0]["entity_count"] == 3


async def test_update_token_entities(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="upd-ent", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.update_token_entities(token["id"], ["switch.b", "fan.c"])
    entities = await db.get_token_entities(token["id"])
    assert set(entities) == {"switch.b", "fan.c"}


async def test_update_token_expiry(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="upd-exp", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    new_expiry = now + 7200
    await db.update_token_expiry(token["id"], new_expiry)
    row = await db.get_token_by_id(token["id"])
    assert row["expires_at"] == new_expiry


async def test_revoke_token(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="rev", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.revoke_token(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["revoked"] == 1


async def test_hard_delete_cascades(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="hard-del", entity_ids=["light.a", "switch.b"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    tid = token["id"]
    await db.delete_token(tid)
    assert await db.get_token_by_id(tid) is None
    # Entities should be cascade-deleted
    entities = await db.get_token_entities(tid)
    assert entities == []


async def test_touch_updates_last_accessed(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="touch", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    assert token["last_accessed"] is None
    await db.touch_token(token["id"])
    row = await db.get_token_by_id(token["id"])
    assert row["last_accessed"] is not None
    assert row["last_accessed"] >= now


async def test_entity_deduplication(test_db):
    """Duplicate entity_ids in create should be stored once."""
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="dedup", entity_ids=["light.a", "light.a", "light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    entities = await db.get_token_entities(token["id"])
    assert entities == ["light.a"]


# ---------------------------------------------------------------------------
# Access log
# ---------------------------------------------------------------------------

async def test_log_access_inserts_row(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="log-test", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.log_access(
        token_id=token["id"],
        event_type="command",
        ip_address="192.168.1.100",
        user_agent="TestAgent/1.0",
        entity_id="light.a",
        service="light.turn_on",
    )
    conn = await db.get_db()
    async with conn.execute(
        "SELECT * FROM access_log WHERE token_id = ?", (token["id"],)
    ) as cur:
        row = await cur.fetchone()
    assert row is not None
    assert row["event_type"] == "command"
    assert row["ip_address"] == "192.168.1.100"
    assert row["entity_id"] == "light.a"
    assert row["service"] == "light.turn_on"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

async def test_cleanup_removes_old_access_logs(test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Test", slug="cleanup-log", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    conn = await db.get_db()
    # Insert an old log entry (100 days ago)
    await conn.execute(
        "INSERT INTO access_log (token_id, timestamp, event_type) VALUES (?, ?, ?)",
        (token["id"], now - 100 * 86400, "command"),
    )
    await conn.commit()

    await db.cleanup_old_data(retention_days=90)

    async with conn.execute("SELECT COUNT(*) as cnt FROM access_log") as cur:
        row = await cur.fetchone()
    assert row["cnt"] == 0


async def test_cleanup_removes_expired_admin_sessions(test_db):
    conn = await db.get_db()
    now = int(time.time())
    await conn.execute(
        "INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)",
        ("old-session", now - 200, now - 100),
    )
    await conn.commit()

    await db.cleanup_old_data(retention_days=90)

    async with conn.execute(
        "SELECT * FROM admin_sessions WHERE id = 'old-session'"
    ) as cur:
        row = await cur.fetchone()
    assert row is None


async def test_cleanup_does_not_delete_never_expires_revoked_tokens(test_db):
    """Revoked never-expires tokens should survive cleanup."""
    now = int(time.time())
    token = await db.create_token(
        label="Forever", slug="never-exp", entity_ids=["light.a"],
        expires_at=NEVER_EXPIRES_SECONDS, ip_allowlist=None,
    )
    await db.revoke_token(token["id"])

    await db.cleanup_old_data(retention_days=1)

    row = await db.get_token_by_id(token["id"])
    assert row is not None
