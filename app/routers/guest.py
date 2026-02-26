"""Guest API router: PWA shell, state, SSE, and command proxy."""
# Security note: The slug in the URL acts as a bearer token — knowing the
# slug grants access. CSRF is mitigated by the fact that all state-changing
# operations require the slug in the URL path (not a cookie). The admin
# dashboard uses SameSite=strict cookies for CSRF protection.
import asyncio
import ipaddress
import json
import re
import time
from typing import AsyncIterator

import httpx
from fastapi import APIRouter, HTTPException, Path, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import database as db
from app import ha_client
from app.config import settings
from app.models import CommandRequest, NEVER_EXPIRES_SECONDS
from app.rate_limiter import rate_limiter

router = APIRouter(prefix="/g")

# L-31: Named constant for SSE keepalive interval
SSE_KEEPALIVE_SECONDS = 25

# Global rate limit for guest command proxy (requests per minute per token).
# Hardcoded — no comparable self-hosted app exposes per-user rate limits.
COMMAND_RPM = 30

# L-8: Whitelist of allowed SSE event types
_ALLOWED_SSE_EVENTS = {"state_change", "token_expired", "reconnected"}

# M-27: Simple TTL cache for HA state list
_states_cache: list[dict] | None = None
_states_cache_ts: float = 0
STATE_CACHE_TTL = 30  # seconds


async def _get_cached_states() -> list[dict]:
    global _states_cache, _states_cache_ts
    now = time.monotonic()
    if _states_cache is not None and (now - _states_cache_ts) < STATE_CACHE_TTL:
        return _states_cache
    _states_cache = await ha_client.get_states()
    _states_cache_ts = now
    return _states_cache


# Services guests are permitted to call, keyed by entity domain.
# Script/scene/automation domains are intentionally excluded —
# they execute arbitrary automations and bypass entity scoping.
ALLOWED_SERVICES: dict[str, set[str]] = {
    "light":         {"turn_on", "turn_off", "toggle"},
    "switch":        {"turn_on", "turn_off", "toggle"},
    "input_boolean": {"turn_on", "turn_off", "toggle"},
    "climate":       {"set_temperature", "set_hvac_mode", "turn_on", "turn_off"},
    "lock":          {"lock", "unlock"},
    "media_player":  {"media_play", "media_pause", "media_stop", "volume_set",
                      "media_play_pause", "turn_on", "turn_off"},
    "cover":         {"open_cover", "close_cover", "stop_cover"},
    "fan":           {"turn_on", "turn_off", "toggle", "set_percentage"},
}

# Keys that could bypass the entity allowlist if forwarded to HA
FORBIDDEN_DATA_KEYS = {"entity_id", "device_id", "area_id", "floor_id"}

templates = Jinja2Templates(directory="templates")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """Extract the client IP from X-Forwarded-For (set by reverse proxy).

    IMPORTANT: HAPass MUST be deployed behind a reverse proxy (Caddy, nginx,
    Cloudflare Tunnel, etc.) that overwrites the X-Forwarded-For header with the
    true client IP. Without this, clients can spoof their IP to bypass allowlists.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _validate_token(slug: str, request: Request):
    """Load and validate a token by slug. Raises HTTP 410 on any issue."""
    row = await db.get_token_by_slug(slug)
    if not row:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Token not found")

    now = int(time.time())
    if row["revoked"] or row["expires_at"] <= now:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Token expired or revoked")

    if row["ip_allowlist"]:
        client_ip = _client_ip(request)
        allowed_cidrs: list[str] = json.loads(row["ip_allowlist"])
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid client IP")
        if not any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP not allowed")

    return row


# ---------------------------------------------------------------------------
# PWA shell
# ---------------------------------------------------------------------------

@router.get("/{slug}", response_class=HTMLResponse)
async def guest_pwa(request: Request, slug: str = Path(max_length=64)):
    row = await db.get_token_by_slug(slug)
    expired = False
    if not row or row["revoked"] or row["expires_at"] <= int(time.time()):
        expired = True

    if expired:
        return templates.TemplateResponse(
            "expired.html",
            {"request": request, "slug": slug, "app_name": settings.app_name, "contact_message": settings.contact_message, "brand_bg": settings.brand_bg, "brand_primary": settings.brand_primary, "csp_nonce": request.state.csp_nonce},
            status_code=410,
        )

    await db.touch_token(row["id"])
    await db.log_access(
        token_id=row["id"],
        event_type="page_load",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return templates.TemplateResponse(
        "guest_pwa.html",
        {"request": request, "slug": slug, "label": row["label"], "expires_at": row["expires_at"], "app_name": settings.app_name, "contact_message": settings.contact_message, "never_expires": NEVER_EXPIRES_SECONDS, "brand_bg": settings.brand_bg, "brand_primary": settings.brand_primary, "csp_nonce": request.state.csp_nonce},
    )


# ---------------------------------------------------------------------------
# Dynamic PWA manifest
# ---------------------------------------------------------------------------

@router.get("/{slug}/manifest.json")
async def guest_manifest(request: Request, slug: str = Path(max_length=64)):
    manifest = {  # colors must match static/input.css
        "name": settings.app_name,
        "short_name": settings.app_name[:12],
        "description": "Temporary home controls",
        "start_url": f"/g/{slug}",
        "scope": f"/g/{slug}",
        "display": "standalone",
        "background_color": settings.brand_bg,
        "theme_color": settings.brand_primary,
        "orientation": "portrait",
        "icons": [
            {"src": "/static/icons/icon-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "any"},
            {"src": "/static/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any"},
            {"src": "/static/icons/icon-maskable-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "maskable"},
            {"src": "/static/icons/icon-maskable-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "maskable"},
        ],
    }
    from fastapi.responses import JSONResponse
    return JSONResponse(manifest)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

@router.get("/{slug}/state")
async def guest_state(request: Request, slug: str = Path(max_length=64)):
    row = await _validate_token(slug, request)
    entity_ids = await db.get_token_entities(row["id"])

    allowed = set(entity_ids)
    all_states = await _get_cached_states()
    states = {}
    for s in all_states:
        eid = s.get("entity_id", "")
        if eid in allowed:
            states[eid] = s
    for eid in entity_ids:
        if eid not in states:
            states[eid] = {"entity_id": eid, "state": "unavailable", "attributes": {}}

    return {"entities": entity_ids, "states": states}


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

async def _event_generator(token_id: str, slug: str, request: Request) -> AsyncIterator[str]:
    q = await ha_client.subscribe(token_id)
    try:
        # M-5: Expose WS health in SSE connected event
        yield f"event: connected\ndata: {{\"ws_healthy\": {str(ha_client.is_ws_healthy()).lower()}}}\n\n"

        while True:
            if await request.is_disconnected():
                break

            try:
                event = await asyncio.wait_for(q.get(), timeout=SSE_KEEPALIVE_SECONDS)
                # L-8: Only forward whitelisted event types
                if event["type"] not in _ALLOWED_SSE_EVENTS:
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                if event["type"] == "token_expired":
                    break
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    finally:
        await ha_client.unsubscribe(token_id, q)


@router.get("/{slug}/stream")
async def guest_stream(request: Request, slug: str = Path(max_length=64)):
    row = await _validate_token(slug, request)
    return StreamingResponse(
        _event_generator(row["id"], slug, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Command proxy
# ---------------------------------------------------------------------------

@router.post("/{slug}/command")
async def guest_command(body: CommandRequest, request: Request, slug: str = Path(max_length=64)):
    row = await _validate_token(slug, request)
    token_id = row["id"]

    allowed = await rate_limiter.check(token_id, COMMAND_RPM)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    # L-6: Validate service format before processing
    if not re.match(r'^[a-z_]+\.[a-z_]+$', body.service) and not re.match(r'^[a-z_]+$', body.service):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid service format")

    entity_ids = await db.get_token_entities(token_id)
    if body.entity_id not in entity_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Entity not in allowlist")

    entity_domain = body.entity_id.split(".")[0]

    if "." in body.service:
        svc_domain, svc_name = body.service.split(".", 1)
        if svc_domain != entity_domain:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Service domain does not match entity")
    else:
        svc_name = body.service

    allowed_svc = ALLOWED_SERVICES.get(entity_domain)
    if not allowed_svc or svc_name not in allowed_svc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Service '{svc_name}' not allowed for {entity_domain}")

    clean_data = {k: v for k, v in body.data.items() if k not in FORBIDDEN_DATA_KEYS}
    service_data = {**clean_data, "entity_id": body.entity_id}

    try:
        result = await ha_client.call_service(entity_domain, svc_name, service_data)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Home Assistant returned {exc.response.status_code}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Home Assistant service call failed")

    await db.log_access(
        token_id=token_id,
        event_type="command",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        entity_id=body.entity_id,
        service=body.service,
    )

    return {"ok": True, "result": result}
