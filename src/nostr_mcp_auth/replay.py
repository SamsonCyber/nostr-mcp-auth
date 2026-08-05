"""Process-local anti-replay cache for NIP-98 event ids."""
from __future__ import annotations

import threading
import time


class ReplayCache:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = max(1, int(ttl_seconds))
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        dead = [k for k, exp in self._seen.items() if exp <= now]
        for k in dead:
            del self._seen[k]

    def seen_or_add(self, event_id: str, *, now: float | None = None) -> bool:
        """Return True if already seen (replay). Else record and return False."""
        ts = time.time() if now is None else float(now)
        with self._lock:
            self._purge(ts)
            if event_id in self._seen:
                return True
            self._seen[event_id] = ts + self.ttl
            return False
