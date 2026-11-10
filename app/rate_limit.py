from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(RuntimeError):
    pass


class SlidingWindowLimiter:
    def __init__(self):
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()

    def check(self, bucket: str, key: str, *, limit: int, seconds: int) -> None:
        now, threshold = time.monotonic(), time.monotonic() - seconds
        identity = (bucket, key)
        with self._lock:
            events = self._events[identity]
            while events and events[0] <= threshold:
                events.popleft()
            if len(events) >= limit:
                raise RateLimitExceeded(bucket)
            events.append(now)
