"""
app/helpers.py
==============

Listing helpers (paging, LIKE escaping) and the in-memory per-IP rate limiter.

Two unrelated concerns share this module because both are small, stateless
request-shaping utilities that the routes reach for and nothing else depends on.
"""

from __future__ import annotations

import time
from collections import defaultdict

from flask import request

from app.config import (
    ADMIN_RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
    RATE_LIMIT_MAX_IPS,
    RATE_LIMIT_WINDOW,
    TRUST_PROXY,
)

PAGE_SIZE = 25

_rate_log: dict[str, list[float]] = defaultdict(list)  # ip -> recent request times


def paginate(page: int, total: int, per_page: int = PAGE_SIZE):
    """Clamp `page` into range. Returns (page, n_pages, offset)."""
    pages = max(1, -(-total // per_page))
    page = min(max(page or 1, 1), pages)
    return page, pages, (page - 1) * per_page


def like_term(text: str) -> str:
    """Wrap a user-supplied search string for LIKE ... ESCAPE '\\'.

    The wildcards are escaped so that searching for a literal '%' or '_' does
    not match every row.
    """
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def client_ip() -> str:
    """The address to rate-limit this request against.

    `X-Forwarded-For` is a client-supplied header. Reading it unconditionally
    let a caller name their own bucket -- rotating it gave every request a
    fresh budget, so the limiter counted nothing at all. It is only consulted
    when this process is knowingly deployed behind a proxy that sets it, and
    then only its first entry (the original client; the rest are appended by
    each hop and are equally forgeable).
    """
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _evict_idle(now: float) -> None:
    """Forget IPs with nothing left in their window.

    `_rate_log` is a defaultdict that only ever grew: every distinct address
    ever seen kept an entry for the life of the process, which an attacker
    could inflate at will. Sweeping is O(tracked IPs) and only runs when the
    table is already over budget.
    """
    # The longest window in use, so sweeping never hands a slower bucket
    # (admin login) a fresh budget early.
    idle_after = max(RATE_LIMIT_WINDOW, ADMIN_RATE_LIMIT_WINDOW)
    for ip in [ip for ip, seen in _rate_log.items()
               if not seen or now - seen[-1] >= idle_after]:
        del _rate_log[ip]


def rate_limited(ip: str, max_calls: int = RATE_LIMIT_MAX,
                 window_secs: int = RATE_LIMIT_WINDOW, bucket: str = "verify") -> bool:
    """Has this address used up its budget for `bucket` in the last window?"""
    now = time.monotonic()
    if len(_rate_log) > RATE_LIMIT_MAX_IPS:
        _evict_idle(now)
    seen = _rate_log[f"{bucket}:{ip}"]
    seen[:] = [t for t in seen if now - t < window_secs]
    if len(seen) >= max_calls:
        return True
    seen.append(now)
    return False
