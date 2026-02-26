"""Tests for guest endpoint security: service allowlists, token validation, IP, rate limiting.

These are integration tests. The full request path is exercised:
    httpx → FastAPI routing → _validate_token (real DB) → service allowlist
    → rate limiter (real) → data scrubbing → ha_client.call_service (mocked)
    → access log (real DB)

Only ha_client is mocked — it's an external dependency we can't run in CI.
"""
import time

import pytest

from app import database as db
from app.routers.guest import ALLOWED_SERVICES, FORBIDDEN_DATA_KEYS


# ---------------------------------------------------------------------------
# ALLOWED_SERVICES — verify the real allowlist enforcement
# ---------------------------------------------------------------------------

async def test_allowed_service_forwards_correct_args_to_ha(client, sample_token, mock_ha_client):
    """A valid command passes all validation and reaches HA with correct args."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    assert resp.status_code == 200

    # Verify call_service was called with the right domain, service, and data
    mock_ha_client["call_service"].assert_called_once()
    args = mock_ha_client["call_service"].call_args[0]
    assert args[0] == "light"       # domain
    assert args[1] == "turn_on"     # service name
    assert args[2]["entity_id"] == "light.living_room"  # entity in payload


async def test_allowed_service_writes_access_log(client, sample_token, mock_ha_client):
    """A successful command writes a row to the real access_log table."""
    await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "turn_on"},
    )
    conn = await db.get_db()
    async with conn.execute(
        "SELECT * FROM access_log WHERE token_id = ?", (sample_token["id"],)
    ) as cur:
        row = await cur.fetchone()
    assert row is not None
    assert row["event_type"] == "command"
    assert row["entity_id"] == "light.living_room"
    assert row["service"] == "turn_on"


async def test_disallowed_service_never_reaches_ha(client, sample_token, mock_ha_client):
    """An unknown service is blocked BEFORE call_service is ever invoked."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "nonexistent_service"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_script_domain_never_reaches_ha(client, mock_ha_client, test_db):
    """Script domain is not in ALLOWED_SERVICES — blocked before HA call."""
    assert "script" not in ALLOWED_SERVICES
    now = int(time.time())
    await db.create_token(
        label="Script", slug="script-test", entity_ids=["script.dangerous"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/script-test/command",
        json={"entity_id": "script.dangerous", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_automation_domain_never_reaches_ha(client, mock_ha_client, test_db):
    assert "automation" not in ALLOWED_SERVICES
    now = int(time.time())
    await db.create_token(
        label="Auto", slug="auto-test", entity_ids=["automation.run_all"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/auto-test/command",
        json={"entity_id": "automation.run_all", "service": "trigger"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


async def test_service_domain_mismatch_rejected(client, sample_token, mock_ha_client):
    """Service domain must match entity domain (light entity vs switch.turn_on)."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "switch.turn_on"},
    )
    assert resp.status_code == 403
    assert "domain does not match" in resp.json()["detail"]
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# FORBIDDEN_DATA_KEYS — real data scrubbing in the router
# ---------------------------------------------------------------------------

async def test_forbidden_data_keys_stripped_before_ha_call(client, sample_token, mock_ha_client):
    """entity_id/device_id/area_id in the data payload are stripped before reaching HA."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={
            "entity_id": "light.living_room",
            "service": "turn_on",
            "data": {
                "brightness": 255,
                "entity_id": "light.MALICIOUS",
                "device_id": "injected",
                "area_id": "sneaky",
            },
        },
    )
    assert resp.status_code == 200

    # Inspect what was actually forwarded to HA
    service_data = mock_ha_client["call_service"].call_args[0][2]
    assert service_data["entity_id"] == "light.living_room"  # real entity, not injected
    assert "device_id" not in service_data
    assert "area_id" not in service_data
    assert service_data["brightness"] == 255  # legitimate data preserved


async def test_all_forbidden_keys_are_scrubbed(client, sample_token, mock_ha_client):
    """Every key in FORBIDDEN_DATA_KEYS is stripped."""
    data_payload = {key: "injected" for key in FORBIDDEN_DATA_KEYS}
    data_payload["brightness"] = 128  # legitimate key

    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={
            "entity_id": "light.living_room",
            "service": "turn_on",
            "data": data_payload,
        },
    )
    assert resp.status_code == 200
    service_data = mock_ha_client["call_service"].call_args[0][2]
    for key in FORBIDDEN_DATA_KEYS:
        if key == "entity_id":
            # entity_id is re-added with the real value
            assert service_data[key] == "light.living_room"
        else:
            assert key not in service_data


# ---------------------------------------------------------------------------
# Token validation — real DB lookups in _validate_token
# ---------------------------------------------------------------------------

async def test_expired_token_returns_410(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="Expired", slug="expired-tok", entity_ids=["light.a"],
        expires_at=now - 1, ip_allowlist=None,
    )
    resp = await client.post(
        "/g/expired-tok/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    mock_ha_client["call_service"].assert_not_called()


async def test_revoked_token_returns_410(client, mock_ha_client, test_db):
    now = int(time.time())
    token = await db.create_token(
        label="Revoked", slug="revoked-tok", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    await db.revoke_token(token["id"])
    resp = await client.post(
        "/g/revoked-tok/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    mock_ha_client["call_service"].assert_not_called()


async def test_nonexistent_slug_returns_410(client, mock_ha_client, test_db):
    resp = await client.post(
        "/g/does-not-exist/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 410
    mock_ha_client["call_service"].assert_not_called()


async def test_entity_not_in_allowlist_returns_403(client, sample_token, mock_ha_client):
    """Entity must be in the token's entity list (checked via real DB query)."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.NOT_ALLOWED", "service": "turn_on"},
    )
    assert resp.status_code == 403
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# IP allowlist — real ipaddress validation
# ---------------------------------------------------------------------------

async def test_ip_allowlist_blocks_non_matching(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="IP", slug="ip-block", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=["10.0.0.0/8"],
    )
    # testserver client comes from 127.0.0.1 — not in 10.0.0.0/8
    resp = await client.post(
        "/g/ip-block/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 403
    assert "IP not allowed" in resp.json()["detail"]
    mock_ha_client["call_service"].assert_not_called()


async def test_ip_allowlist_allows_matching(client, mock_ha_client, test_db):
    now = int(time.time())
    await db.create_token(
        label="IP", slug="ip-allow", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=["127.0.0.0/8"],
    )
    resp = await client.post(
        "/g/ip-allow/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 200
    mock_ha_client["call_service"].assert_called_once()


# ---------------------------------------------------------------------------
# Rate limiting — real rate_limiter singleton
# ---------------------------------------------------------------------------

async def test_rate_limit_returns_429(client, mock_ha_client, test_db):
    """Exhaust the global 30 RPM limit and verify 429 is returned."""
    from app.routers.guest import COMMAND_RPM

    now = int(time.time())
    await db.create_token(
        label="Rate", slug="rate-test", entity_ids=["light.a"],
        expires_at=now + 3600, ip_allowlist=None,
    )
    # Exhaust the global RPM limit
    for i in range(COMMAND_RPM):
        resp = await client.post(
            "/g/rate-test/command",
            json={"entity_id": "light.a", "service": "turn_on"},
        )
        assert resp.status_code == 200

    # Next request is blocked
    resp = await client.post(
        "/g/rate-test/command",
        json={"entity_id": "light.a", "service": "turn_on"},
    )
    assert resp.status_code == 429
    assert mock_ha_client["call_service"].call_count == COMMAND_RPM


# ---------------------------------------------------------------------------
# Service format validation — real regex in the router
# ---------------------------------------------------------------------------

async def test_service_injection_attempt_returns_422(client, sample_token, mock_ha_client):
    """Shell metacharacters in service name are caught by regex validation."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "light.turn_on; rm -rf /"},
    )
    assert resp.status_code == 422
    mock_ha_client["call_service"].assert_not_called()


async def test_service_with_uppercase_rejected(client, sample_token, mock_ha_client):
    """Service format regex only allows lowercase + underscores."""
    resp = await client.post(
        f"/g/{sample_token['slug']}/command",
        json={"entity_id": "light.living_room", "service": "light.TURN_ON"},
    )
    assert resp.status_code == 422
    mock_ha_client["call_service"].assert_not_called()


# ---------------------------------------------------------------------------
# Guest PWA page rendering — real template rendering + DB lookup
# ---------------------------------------------------------------------------

async def test_guest_pwa_valid_token_renders_page(client, sample_token, mock_ha_client):
    """A valid token slug renders the guest PWA page and touches the token."""
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Token should have been touched (last_accessed updated)
    row = await db.get_token_by_id(sample_token["id"])
    assert row["last_accessed"] is not None


async def test_guest_pwa_expired_token_renders_expired_page(client, mock_ha_client, test_db):
    """An expired token renders the expired page with 410."""
    now = int(time.time())
    await db.create_token(
        label="Old", slug="old-link", entity_ids=["light.a"],
        expires_at=now - 1, ip_allowlist=None,
    )
    resp = await client.get("/g/old-link")
    assert resp.status_code == 410
    assert "text/html" in resp.headers["content-type"]


async def test_guest_pwa_nonexistent_slug_renders_expired_page(client, mock_ha_client, test_db):
    """A slug that doesn't exist renders the expired page with 410."""
    resp = await client.get("/g/does-not-exist")
    assert resp.status_code == 410


# ---------------------------------------------------------------------------
# Security headers — real middleware on every response
# ---------------------------------------------------------------------------

async def test_security_headers_on_guest_route(client, sample_token, mock_ha_client):
    """Guest routes get nonce-based CSP (no unsafe-inline for scripts)."""
    resp = await client.get(f"/g/{sample_token['slug']}")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    csp = resp.headers["content-security-policy"]
    assert "'nonce-" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]


async def test_security_headers_on_admin_route(client, admin_session, mock_ha_client):
    """Admin routes use nonce-based CSP (inline handlers migrated to event delegation)."""
    resp = await client.get("/admin/tokens", cookies=admin_session)
    csp = resp.headers["content-security-policy"]
    script_src_section = csp.split("script-src")[1].split(";")[0]
    assert "'nonce-" in script_src_section
    assert "'unsafe-inline'" not in script_src_section
