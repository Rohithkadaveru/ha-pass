"""Guest API router: PWA shell, state, SSE, and command proxy."""
# Security note: The slug in the URL acts as a bearer token — knowing the
# slug grants access. CSRF is mitigated by the fact that all state-changing
# operations require the slug in the URL path (not a cookie). The admin
# dashboard uses SameSite=strict cookies for CSRF protection.
import asyncio
import ipaddress
import json
import logging
import re
import time
from typing import AsyncIterator

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Path, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import database as db
from app import ha_client
from app.config import settings
from app.context import base_context
from app.models import (
    ALLOWED_SERVICES,
    CommandRequest,
    FORBIDDEN_DATA_KEYS,
    NEVER_EXPIRES_SECONDS,
)
from app.rate_limiter import rate_limiter

router = APIRouter(prefix="/g")
logger = logging.getLogger(__name__)

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
ACTIVITY_EVENT_TYPE = "ha_pass_activity"
ACTIVITY_SCHEMA_VERSION = 1
PAGE_LOAD_EVENT_DEBOUNCE_SECONDS = 30
_page_load_activity_ts: dict[str, float] = {}


async def _get_cached_states() -> list[dict]:
    global _states_cache, _states_cache_ts
    now = time.monotonic()
    if _states_cache is not None and (now - _states_cache_ts) < STATE_CACHE_TTL:
        return _states_cache
    _states_cache = await ha_client.get_states()
    _states_cache_ts = now
    return _states_cache


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


def _enforce_ip_allowlist(row, request: Request) -> None:
    if not row["ip_allowlist"]:
        return
    client_ip = _client_ip(request)
    allowed_cidrs: list[str] = json.loads(row["ip_allowlist"])
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid client IP")
    if not any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP not allowed")


async def _validate_token(slug: str, request: Request):
    """Load and validate a token by slug. Raises HTTP 410 on any issue."""
    row = await db.get_token_by_slug(slug)
    if not row:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Access unavailable")

    now = int(time.time())
    if row["revoked"] or row["expires_at"] <= now:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Access unavailable")

    _enforce_ip_allowlist(row, request)

    return row


async def _fire_activity_event(payload: dict) -> None:
    try:
        await ha_client.fire_event(ACTIVITY_EVENT_TYPE, payload)
    except Exception as exc:
        logger.warning("Failed to emit HA activity event: %s", exc)
    try:
        await ha_client.logbook_log(_logbook_payload(payload))
    except Exception as exc:
        logger.warning("Failed to write HA logbook activity: %s", exc)


def _logbook_payload(payload: dict) -> dict:
    token_label = payload["token_label"]
    if payload["activity"] == "command":
        target_entity_id = payload["target_entity_id"]
        data = {
            "name": "HAPass",
            "message": f"{token_label} used {payload['service']} on {target_entity_id}",
            "entity_id": target_entity_id,
        }
        if target_entity_id and "." in target_entity_id:
            data["domain"] = target_entity_id.split(".", 1)[0]
        return data
    return {
        "name": "HAPass",
        "message": f"{token_label} opened guest link",
    }


def _activity_payload(
    row,
    activity: str,
    target_entity_id: str | None = None,
    service: str | None = None,
) -> dict:
    return {
        "schema_version": ACTIVITY_SCHEMA_VERSION,
        "activity": activity,
        "token_label": row["label"],
        "target_entity_id": target_entity_id,
        "service": service,
    }


def _schedule_activity_event(background_tasks: BackgroundTasks, payload: dict) -> None:
    background_tasks.add_task(_fire_activity_event, payload)


def _schedule_page_load_activity(background_tasks: BackgroundTasks, row) -> None:
    now = time.monotonic()
    cutoff = now - PAGE_LOAD_EVENT_DEBOUNCE_SECONDS
    for token_id, last_emitted in list(_page_load_activity_ts.items()):
        if last_emitted < cutoff:
            del _page_load_activity_ts[token_id]
    token_id = row["id"]
    last_emitted = _page_load_activity_ts.get(token_id)
    if last_emitted is not None and (now - last_emitted) < PAGE_LOAD_EVENT_DEBOUNCE_SECONDS:
        return
    _page_load_activity_ts[token_id] = now
    _schedule_activity_event(background_tasks, _activity_payload(row, "page_load"))


# ---------------------------------------------------------------------------
# PWA shell
# ---------------------------------------------------------------------------

@router.get("/{slug}", response_class=HTMLResponse)
async def guest_pwa(background_tasks: BackgroundTasks, request: Request, slug: str = Path(max_length=64)):
    row = await db.get_token_by_slug(slug)
    expired = False
    if not row or row["revoked"] or row["expires_at"] <= int(time.time()):
        expired = True

    if expired:
        ctx = base_context(request)
        ctx.update({"slug": slug, "contact_message": settings.contact_message})
        return templates.TemplateResponse(request, "expired.html", ctx, status_code=410)

    try:
        _enforce_ip_allowlist(row, request)
    except HTTPException as exc:
        ctx = base_context(request)
        ctx.update({"slug": slug, "contact_message": settings.contact_message})
        return templates.TemplateResponse(request, "expired.html", ctx, status_code=exc.status_code)
    await db.touch_token(row["id"])
    await db.log_access(
        token_id=row["id"],
        event_type="page_load",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    _schedule_page_load_activity(background_tasks, row)
    ctx = base_context(request)
    ctx.update({
        "slug": slug,
        "label": row["label"],
        "expires_at": row["expires_at"],
        "contact_message": settings.contact_message,
        "never_expires": NEVER_EXPIRES_SECONDS,
    })
    return templates.TemplateResponse(request, "guest_pwa.html", ctx)


# ---------------------------------------------------------------------------
# Dynamic PWA manifest
# ---------------------------------------------------------------------------

@router.get("/{slug}/manifest.json")
async def guest_manifest(request: Request, slug: str = Path(max_length=64)):
    bp = request.state.ingress_path
    manifest = {  # colors must match static/input.css
        "name": settings.app_name,
        "short_name": settings.app_name[:12],
        "description": "Temporary home controls",
        "start_url": f"{bp}/g/{slug}",
        "scope": f"{bp}/g/{slug}",
        "display": "standalone",
        "background_color": settings.brand_bg,
        "theme_color": settings.brand_primary,
        "orientation": "portrait",
        "icons": [
            {"src": f"{bp}/static/icons/icon-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any"},
            {"src": f"{bp}/static/icons/icon-maskable-192.png", "sizes": "192x192",
             "type": "image/png", "purpose": "maskable"},
            {"src": f"{bp}/static/icons/icon-maskable-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "maskable"},
        ],
    }
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
async def guest_command(
    body: CommandRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    slug: str = Path(max_length=64),
):
    row = await _validate_token(slug, request)
    token_id = row["id"]

    allowed = await rate_limiter.check(token_id, COMMAND_RPM)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    # L-6: Validate service format before processing
    if not re.match(r'^[a-z_]+\.[a-z_]+$', body.service) and not re.match(r'^[a-z_]+$', body.service):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid service format",
        )

    entity_ids = await db.get_token_entities(token_id)
    if body.entity_id not in entity_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Entity not in allowlist")

    entity_domain = body.entity_id.split(".")[0]

    if "." in body.service:
        svc_domain, svc_name = body.service.split(".", 1)
        if svc_domain != entity_domain:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Service domain does not match entity",
            )
    else:
        svc_name = body.service

    allowed_svc = ALLOWED_SERVICES.get(entity_domain)
    if not allowed_svc or svc_name not in allowed_svc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Service '{svc_name}' not allowed for {entity_domain}",
        )

    clean_data = {k: v for k, v in body.data.items() if k not in FORBIDDEN_DATA_KEYS}
    service_data = {**clean_data, "entity_id": body.entity_id}

    try:
        result = await ha_client.call_service(entity_domain, svc_name, service_data)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Service call failed")
    except Exception:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Service call failed")

    await db.log_access(
        token_id=token_id,
        event_type="command",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        entity_id=body.entity_id,
        service=body.service,
    )
    _schedule_activity_event(
        background_tasks,
        _activity_payload(
            row,
            "command",
            target_entity_id=body.entity_id,
            service=f"{entity_domain}.{svc_name}",
        ),
    )

    return {"ok": True}
