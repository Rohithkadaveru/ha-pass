"""Per-token sliding-window rate limiter (in-memory)."""
import asyncio
import time
from collections import deque


class RateLimiter:
    WINDOW_SECONDS = 60.0

    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, token_id: str, limit_rpm: int) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        now = time.monotonic()
        window_start = now - self.WINDOW_SECONDS

        async with self._lock:
            dq = self._windows.setdefault(token_id, deque())
            # Drop timestamps outside the window
            while dq and dq[0] < window_start:
                dq.popleft()

            if len(dq) >= limit_rpm:
                return False

            dq.append(now)
            return True

    async def cleanup(self) -> None:
        """Remove entries for tokens with no recent requests (call periodically)."""
        now = time.monotonic()
        window_start = now - self.WINDOW_SECONDS
        async with self._lock:
            stale = [tid for tid, dq in self._windows.items() if not dq or dq[-1] < window_start]
            for tid in stale:
                del self._windows[tid]


rate_limiter = RateLimiter()
