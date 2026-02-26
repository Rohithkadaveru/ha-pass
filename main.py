"""HAPass — FastAPI entry point."""
import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import database as db
from app import ha_client
from app.config import settings
from app.rate_limiter import rate_limiter
from app.routers import admin, guest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

CLEANUP_INTERVAL_SECONDS = 300


@asynccontextmanager
async def lifespan(app: FastAPI):
    # L-3: Wrap DB creation in try/except
    try:
        os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
        db.run_migrations()
        await db.get_db()
        logger.info("Database ready at %s", settings.db_path)
    except Exception as exc:
        logger.critical("Failed to initialize database at %s: %s", settings.db_path, exc)
        raise RuntimeError(f"Database initialization failed: {exc}") from exc

    ha_client.init_client()  # sync — no await

    try:
        await ha_client.validate_connectivity()
    except Exception as exc:
        logger.error("Cannot reach Home Assistant: %s", exc)
        raise RuntimeError("Home Assistant unreachable at startup") from exc

    await ha_client.start_ws_listener()

    async def _cleanup_loop():
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                await rate_limiter.cleanup()
                await db.cleanup_old_data(settings.access_log_retention_days)
            except Exception:
                logger.exception("Cleanup loop iteration failed")

    # M-2: Add done_callback to detect silent cleanup task death
    cleanup_task = asyncio.create_task(_cleanup_loop())
    cleanup_task.add_done_callback(lambda t: logger.error("Cleanup task terminated: %s", t.exception()) if not t.cancelled() and t.exception() else None)

    yield

    # M-7: Shutdown with timeout
    cleanup_task.cancel()
    try:
        await asyncio.wait_for(ha_client.stop_ws_listener(), timeout=5)
    except asyncio.TimeoutError:
        logger.warning("WS listener stop timed out, forcing cancel")
        if ha_client._ws_task:
            ha_client._ws_task.cancel()
    await ha_client.close_client()
    try:
        await db.close_db()
    except Exception:
        logger.exception("Error closing database")


app = FastAPI(
    title="HAPass",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
_templates = Jinja2Templates(directory="templates")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # All routes use strict nonce-based CSP (M-17: admin inline handlers
    # migrated to event delegation).
    script_src = f"'self' 'nonce-{nonce}'"
    csp = (
        f"default-src 'self'; "
        f"script-src {script_src}; "
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"font-src https://fonts.gstatic.com; "
        f"img-src 'self' data:; "
        f"connect-src 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    # Prevent browser from caching HTML responses (avoids stale JS after deploys)
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(admin.router)
app.include_router(guest.router)


@app.get("/")
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/admin/dashboard")


@app.get("/admin/dashboard", include_in_schema=False)
async def admin_dashboard_page(request: Request):
    from app.models import NEVER_EXPIRES_SECONDS
    return _templates.TemplateResponse("admin_dashboard.html", {"request": request, "app_name": settings.app_name, "never_expires": NEVER_EXPIRES_SECONDS, "brand_bg": settings.brand_bg, "brand_primary": settings.brand_primary, "csp_nonce": request.state.csp_nonce})


# M-6: Health check with WS and DB status
@app.get("/health")
async def health():
    ws_ok = ha_client.is_ws_healthy()
    try:
        await db.get_db()
        db_ok = True
    except Exception:
        db_ok = False
    if ws_ok and db_ok:
        return {"status": "ok", "ws": "connected", "db": "accessible"}
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=503,
        content={"status": "degraded", "ws": "connected" if ws_ok else "disconnected", "db": "accessible" if db_ok else "unavailable"},
    )
