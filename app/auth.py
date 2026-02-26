"""Admin authentication: bcrypt password hashing and session cookie management."""
import asyncio

import bcrypt
from fastapi import Cookie, HTTPException, Request, status

from app import database as db
from app.config import settings

# Hash the configured password once at import time so comparisons are fast.
_hashed: bytes = bcrypt.hashpw(settings.admin_password.encode(), bcrypt.gensalt())

SESSION_COOKIE = "ha_guest_admin_session"


async def verify_password(plain: str) -> bool:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, bcrypt.checkpw, plain.encode(), _hashed)


async def require_admin(request: Request) -> str:
    """FastAPI dependency — raises 401 if no valid session cookie."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    row = await db.get_admin_session(session_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return session_id
