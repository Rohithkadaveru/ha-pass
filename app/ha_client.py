"""Home Assistant client: REST API calls + WebSocket fan-out for SSE."""
import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import websockets
import websockets.exceptions

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Named constants (L-30)
# ---------------------------------------------------------------------------
HTTP_TIMEOUT = 10
QUEUE_SIZE = 64
WS_PING_INTERVAL = 30
WS_BACKOFF_INIT = 2
WS_BACKOFF_MAX = 60
MAX_AUTH_RETRIES = 5

# ---------------------------------------------------------------------------
# Persistent HTTP client
# ---------------------------------------------------------------------------
_client: httpx.AsyncClient | None = None


def _require_client() -> httpx.AsyncClient:
    """Return the persistent client, or raise if not initialized."""
    if _client is None:
        raise RuntimeError("HA client not initialized — call init_client() first")
    return _client


def init_client() -> None:
    global _client
    if _client is not None:
        return  # idempotent — don't orphan existing client
    base = settings.ha_base_url.rstrip("/")
    _client = httpx.AsyncClient(
        base_url=base,
        headers={
            "Authorization": f"Bearer {settings.ha_token}",
            "Content-Type": "application/json",
        },
        timeout=HTTP_TIMEOUT,
    )


async def close_client() -> None:
    global _client
    if _client:
        await _client.aclose()
        _client = None


# ---------------------------------------------------------------------------
# SSE subscription registry + entity cache
# ---------------------------------------------------------------------------
# token_id -> set of asyncio.Queue[dict]
_subscriptions: dict[str, set[asyncio.Queue]] = {}
_entity_cache: dict[str, set[str]] = {}
_sub_lock = asyncio.Lock()


async def subscribe(token_id: str) -> asyncio.Queue:
    """Register a new SSE queue for a token. Returns the queue."""
    from app import database as db

    q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)

    # Fetch entities OUTSIDE the lock to avoid blocking fan-out
    async with _sub_lock:
        needs_fetch = token_id not in _entity_cache
    if needs_fetch:
        entities = await db.get_token_entities(token_id)
        async with _sub_lock:
            if token_id not in _entity_cache:  # re-check after re-acquire
                _entity_cache[token_id] = set(entities)

    async with _sub_lock:
        _subscriptions.setdefault(token_id, set()).add(q)
    return q


async def unsubscribe(token_id: str, q: asyncio.Queue) -> None:
    async with _sub_lock:
        subs = _subscriptions.get(token_id)
        if subs:
            subs.discard(q)
            if not subs:
                del _subscriptions[token_id]
                _entity_cache.pop(token_id, None)


async def invalidate_entity_cache(token_id: str) -> None:
    """Re-populate cache if token has active SSE subscribers, else remove."""
    from app import database as db

    # Check for active subscribers outside the DB call
    async with _sub_lock:
        has_subs = token_id in _subscriptions
    if has_subs:
        try:
            entities = await db.get_token_entities(token_id)
        except Exception:
            logger.exception("Failed to refresh entity cache for %s", token_id)
            async with _sub_lock:
                _entity_cache.pop(token_id, None)
            return
        async with _sub_lock:
            if token_id in _subscriptions:  # re-check: may have unsubscribed
                _entity_cache[token_id] = set(entities)
            else:
                _entity_cache.pop(token_id, None)
    else:
        async with _sub_lock:
            _entity_cache.pop(token_id, None)


async def _fan_out(entity_id: str, new_state: dict) -> None:
    """Push a state_change event to all queues whose token owns the entity."""
    event = {"type": "state_change", "entity_id": entity_id, "state": new_state}
    # Deep-copy sets to avoid RuntimeError if unsubscribe modifies concurrently
    async with _sub_lock:
        snapshot = {tid: set(qs) for tid, qs in _subscriptions.items()}
        cache_snapshot = {tid: frozenset(es) for tid, es in _entity_cache.items()}
    for token_id, queues in snapshot.items():
        allowed = cache_snapshot.get(token_id, frozenset())
        if entity_id in allowed:
            for q in queues:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # slow consumer; drop event


async def broadcast_token_expired(token_id: str) -> None:
    """Push token_expired event to all SSE connections for a token."""
    event = {"type": "token_expired"}
    async with _sub_lock:
        queues = set(_subscriptions.get(token_id, set()))
    for q in queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


# ---------------------------------------------------------------------------
# REST helpers (M-4: retry on transient HTTP errors)
# ---------------------------------------------------------------------------

async def _retry_http(coro_factory, retries=2, backoff_init=1):
    """Retry an HTTP call on transient failures."""
    for attempt in range(retries + 1):
        try:
            return await coro_factory()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500 or attempt == retries:
                raise
            logger.warning("HA HTTP %d, retrying in %ds…", exc.response.status_code, backoff_init * (attempt + 1))
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            if attempt == retries:
                raise
            logger.warning("HA HTTP error: %s, retrying in %ds…", exc, backoff_init * (attempt + 1))
        await asyncio.sleep(backoff_init * (attempt + 1))


async def get_states() -> list[dict]:
    async def _do():
        resp = await _require_client().get("/api/states")
        resp.raise_for_status()
        return resp.json()
    return await _retry_http(_do)


async def call_service(domain: str, service: str, data: dict) -> Any:
    async def _do():
        resp = await _require_client().post(f"/api/services/{domain}/{service}", json=data)
        resp.raise_for_status()
        return resp.json()
    return await _retry_http(_do)


async def validate_connectivity() -> None:
    """Called at startup — raises on failure."""
    resp = await _require_client().get("/api/")
    resp.raise_for_status()
    logger.info("Home Assistant connectivity validated.")


# ---------------------------------------------------------------------------
# WebSocket listener — single persistent connection, fans out to SSE queues
# ---------------------------------------------------------------------------

_ws_task: asyncio.Task | None = None
_msg_id = 1
_ws_healthy: bool = False

# H-5: Store background task refs to prevent GC and log errors
_bg_tasks: set[asyncio.Task] = set()


def _task_done(task: asyncio.Task) -> None:
    _bg_tasks.discard(task)
    if not task.cancelled() and task.exception():
        logger.error("Fan-out task failed: %s", task.exception())


def _build_ws_url() -> str:
    parsed = urlparse(settings.ha_base_url.rstrip("/"))
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse(parsed._replace(scheme=scheme)) + "/api/websocket"


# L-5: Removed module-level _ws_url — built lazily inside _ws_listener


async def _broadcast_reconnected() -> None:
    """Push reconnected event to all SSE connections so they refetch state."""
    event = {"type": "reconnected"}
    async with _sub_lock:
        all_queues = [q for qs in _subscriptions.values() for q in qs]
    for q in all_queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


async def _ws_listener() -> None:
    global _msg_id, _ws_healthy
    ws_url = _build_ws_url()
    backoff = WS_BACKOFF_INIT
    while True:
        try:
            logger.info("Connecting to HA WebSocket at %s", ws_url)
            async with websockets.connect(ws_url, ping_interval=WS_PING_INTERVAL) as ws:
                backoff = WS_BACKOFF_INIT

                # Phase 1: auth
                raw = await ws.recv()
                msg = json.loads(raw)
                if msg.get("type") != "auth_required":
                    logger.warning("Unexpected WS message (expected auth_required): %s", msg.get("type"))
                    continue  # reconnect

                await ws.send(json.dumps({"type": "auth", "access_token": settings.ha_token}))
                raw = await ws.recv()
                msg = json.loads(raw)
                if msg.get("type") != "auth_ok":
                    logger.critical("HA WebSocket auth failed — check HA_TOKEN: %s", msg)
                    _ws_healthy = False
                    return  # Permanent — bad token; don't retry

                # Phase 2: subscribe to state_changed events
                _msg_id = 1
                await ws.send(json.dumps({
                    "id": _msg_id,
                    "type": "subscribe_events",
                    "event_type": "state_changed",
                }))
                raw = await ws.recv()
                msg = json.loads(raw)
                if not msg.get("success"):
                    logger.error("HA subscribe failed: %s", msg)
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, WS_BACKOFF_MAX)
                    continue  # retry

                _ws_healthy = True
                logger.info("HA WebSocket subscribed to state_changed events.")

                # Broadcast reconnected event for SSE clients to refetch
                await _broadcast_reconnected()

                # Phase 3: fan out events
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if msg.get("type") != "event":
                        continue

                    event_data = msg.get("event", {}).get("data", {})
                    new_state = event_data.get("new_state")
                    if not new_state:
                        continue

                    entity_id = new_state.get("entity_id", "")
                    task = asyncio.create_task(_fan_out(entity_id, new_state))
                    _bg_tasks.add(task)
                    task.add_done_callback(_task_done)

        except websockets.exceptions.ConnectionClosed:
            logger.warning("HA WebSocket closed, reconnecting in %ds…", backoff)
        except OSError as exc:
            logger.warning("HA WebSocket OSError: %s — reconnecting in %ds…", exc, backoff)
        except Exception as exc:
            logger.exception("HA WebSocket unexpected error — reconnecting in %ds…", backoff)

        _ws_healthy = False
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, WS_BACKOFF_MAX)


def is_ws_healthy() -> bool:
    """Return True if the WebSocket listener is connected and subscribed."""
    return _ws_healthy and _ws_task is not None and not _ws_task.done()


async def start_ws_listener() -> None:
    global _ws_task
    _ws_task = asyncio.create_task(_ws_listener())
    logger.info("HA WebSocket listener task started.")


async def stop_ws_listener() -> None:
    global _ws_task
    if _ws_task:
        _ws_task.cancel()
        try:
            await _ws_task
        except asyncio.CancelledError:
            pass
        _ws_task = None
