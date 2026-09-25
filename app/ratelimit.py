"""Simple in-memory sliding-window rate limiter (per process)."""
import threading
import time
from collections import defaultdict, deque

_hits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()

# name: (max events, window seconds)
LIMITS = {
    "login": (8, 15 * 60),        # per IP+username
    "signup": (5, 60 * 60),       # per IP
    "add_link": (60, 60 * 60),    # per user
    "quick_share": (10, 60 * 60), # per IP (no login)
    "report": (20, 60 * 60),      # per IP/user
    "friend_request": (30, 60 * 60),
    "share": (60, 60 * 60),
}


def allow(kind: str, key: str) -> bool:
    limit, window = LIMITS[kind]
    now = time.monotonic()
    bucket_key = f"{kind}:{key}"
    with _lock:
        q = _hits[bucket_key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(_hits) > 50_000:  # crude memory cap
            for k in [k for k, v in _hits.items() if not v][:10_000]:
                del _hits[k]
        return True
