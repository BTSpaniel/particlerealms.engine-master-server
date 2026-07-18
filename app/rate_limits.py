# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/rate_limits.py — per-session, per-operation token buckets
(network plan §35 anti-DoS operation limits).
"""

from __future__ import annotations

import time


class TokenBucket:
    __slots__ = ("capacity", "tokens", "refill_per_sec", "last_refill")

    def __init__(self, capacity: float, refill_per_sec: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_per_sec = refill_per_sec
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now

    def try_consume(self, cost: float = 1.0) -> bool:
        self._refill()
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


class RateLimiterRegistry:
    """
    One token bucket per (session_id, operation). Defaults per network plan
    §35: ATTACH_ROUTE 4/minute, SIGNAL 10/sec (burst 30), FORWARD 5/sec.
    """

    DEFAULTS = {
        "MESSAGE": (128.0, 64.0),
        "ATTACH_ROUTE": (4.0, 4.0 / 60.0),
        "SIGNAL": (40.0, 20.0),
        "SIGNAL_V2": (40.0, 20.0),
        "FORWARD": (10.0, 5.0),
        "DISCOVER": (10.0, 2.0),
        "HEARTBEAT": (1.0, 1.0 / 20.0),
        # A proof is deliberately not refillable within one socket lifetime.
        "PROVE": (3.0, 0.0),
    }

    def __init__(self):
        self._buckets: dict[tuple[str, str], TokenBucket] = {}

    def check(self, session_id: str, op: str) -> bool:
        capacity, refill = self.DEFAULTS.get(op, (30.0, 10.0))
        key = (session_id, op)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(capacity, refill)
            self._buckets[key] = bucket
        return bucket.try_consume()

    def drop_session(self, session_id: str) -> None:
        for key in [k for k in self._buckets if k[0] == session_id]:
            del self._buckets[key]
