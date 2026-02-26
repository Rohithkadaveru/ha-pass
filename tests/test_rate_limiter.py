"""Tests for the in-memory sliding-window rate limiter."""
import time
from unittest.mock import patch

import pytest

from app.rate_limiter import RateLimiter


@pytest.fixture
def limiter():
    return RateLimiter()


async def test_allows_within_limit(limiter):
    """N requests under limit all return True."""
    for _ in range(5):
        assert await limiter.check("token-a", 5) is True


async def test_blocks_over_limit(limiter):
    """Request N+1 returns False."""
    for _ in range(5):
        await limiter.check("token-a", 5)
    assert await limiter.check("token-a", 5) is False


async def test_window_slides(limiter):
    """After 60s, old requests expire and new ones are allowed."""
    base = time.monotonic()
    with patch("time.monotonic", return_value=base):
        for _ in range(5):
            await limiter.check("token-a", 5)

    # Advance past the 60-second window
    with patch("time.monotonic", return_value=base + 61):
        assert await limiter.check("token-a", 5) is True


async def test_window_does_not_slide_prematurely(limiter):
    """At exactly 59s, old requests should still count."""
    base = time.monotonic()
    with patch("time.monotonic", return_value=base):
        for _ in range(5):
            await limiter.check("token-a", 5)

    # 59 seconds later — still within the 60-second window
    with patch("time.monotonic", return_value=base + 59):
        assert await limiter.check("token-a", 5) is False


async def test_different_tokens_independent(limiter):
    """Token A's limit doesn't affect token B."""
    for _ in range(5):
        await limiter.check("token-a", 5)
    assert await limiter.check("token-a", 5) is False
    assert await limiter.check("token-b", 5) is True


async def test_cleanup_removes_stale(limiter):
    """cleanup() removes tokens with no recent activity."""
    base = time.monotonic()
    with patch("time.monotonic", return_value=base):
        await limiter.check("token-a", 10)

    with patch("time.monotonic", return_value=base + 61):
        await limiter.cleanup()
        assert "token-a" not in limiter._windows


async def test_cleanup_keeps_active(limiter):
    """Active tokens survive cleanup."""
    await limiter.check("token-a", 10)
    await limiter.cleanup()
    assert "token-a" in limiter._windows


async def test_limit_of_one(limiter):
    """RPM=1 allows exactly one request."""
    assert await limiter.check("token-a", 1) is True
    assert await limiter.check("token-a", 1) is False


async def test_partial_window_expiry(limiter):
    """Only old entries expire; recent ones remain and count."""
    base = time.monotonic()

    # 3 requests at t=0
    with patch("time.monotonic", return_value=base):
        for _ in range(3):
            await limiter.check("token-a", 5)

    # 2 more requests at t=30 (within window)
    with patch("time.monotonic", return_value=base + 30):
        for _ in range(2):
            await limiter.check("token-a", 5)

    # At t=61, the first 3 expired but the 2 from t=30 are still in window
    with patch("time.monotonic", return_value=base + 61):
        assert await limiter.check("token-a", 5) is True  # 2 in window, under 5
        assert await limiter.check("token-a", 5) is True  # 3 in window
        assert await limiter.check("token-a", 5) is True  # 4 in window
        assert await limiter.check("token-a", 5) is False  # 5 = limit, next blocked
