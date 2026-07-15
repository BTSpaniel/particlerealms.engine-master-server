# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/hub.py — all server-side state, in memory only (network
plan §6/§43 no-logging policy: no access logs, no message logs, no IP
database, no peer-history database — everything here resets on restart).

The Hub knows nothing about identity/trust/groups (network plan §12): it
only tracks which (opaque) session_ids are attached to which (opaque)
route_ids, with TTL leases, plus a short-lived seen-packet dedupe cache and
per-session rate limiters. Routes are dynamic (network plan §9) — there is
no create-route call, only attach (which creates the route entry on first
attach) and detach (which removes it once empty).
"""

from __future__ import annotations

import time
import uuid

from .config import Config
from .rate_limits import RateLimiterRegistry


class Hub:
    def __init__(self, config: Config):
        self.config = config
        self.sessions: dict[str, dict] = {}
        self.routes: dict[str, dict[str, float]] = {}
        self._seen: dict[str, float] = {}
        self.rate_limiter = RateLimiterRegistry()

    # ── Sessions ──────────────────────────────────────────────────────────

    def create_session(self, websocket) -> str:
        session_id = uuid.uuid4().hex
        self.sessions[session_id] = {
            "ws": websocket,
            "proven": False,
            "challenge": None,
            "public_key_raw": None,
            "created_at": time.monotonic(),
            "last_heartbeat": time.monotonic(),
            "routes": set(),
        }
        return session_id

    def remove_session(self, session_id: str) -> None:
        sess = self.sessions.pop(session_id, None)
        if not sess:
            return
        for route_id in list(sess["routes"]):
            self.detach_route(session_id, route_id)
        self.rate_limiter.drop_session(session_id)

    def touch_heartbeat(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if sess:
            sess["last_heartbeat"] = time.monotonic()

    def session_count(self) -> int:
        return len(self.sessions)

    # ── Routes (network plan §9) ──────────────────────────────────────────

    def attach_route(self, session_id: str, route_id: str, ttl_seconds: float | None = None) -> None:
        sess = self.sessions.get(session_id)
        if sess is None:
            raise KeyError("unknown session")
        if route_id not in sess["routes"] and len(sess["routes"]) >= self.config.max_routes_per_session:
            raise ValueError("too-many-routes")
        ttl = ttl_seconds if ttl_seconds is not None else self.config.route_lease_seconds
        route = self.routes.setdefault(route_id, {})
        route[session_id] = time.monotonic() + ttl
        sess["routes"].add(route_id)

    def heartbeat_route(self, session_id: str, route_id: str, ttl_seconds: float | None = None) -> bool:
        route = self.routes.get(route_id)
        if not route or session_id not in route:
            return False
        ttl = ttl_seconds if ttl_seconds is not None else self.config.route_lease_seconds
        route[session_id] = time.monotonic() + ttl
        return True

    def detach_route(self, session_id: str, route_id: str) -> None:
        route = self.routes.get(route_id)
        if route is not None:
            route.pop(session_id, None)
            if not route:
                self.routes.pop(route_id, None)
        sess = self.sessions.get(session_id)
        if sess is not None:
            sess["routes"].discard(route_id)

    def route_subscribers(self, route_id: str, exclude: str | None = None) -> list[str]:
        route = self.routes.get(route_id)
        if not route:
            return []
        now = time.monotonic()
        return [sid for sid, expires_at in route.items() if expires_at > now and sid != exclude]

    def prune_routes(self) -> int:
        now = time.monotonic()
        removed = 0
        for route_id in list(self.routes.keys()):
            route = self.routes[route_id]
            for sid in list(route.keys()):
                if route[sid] <= now:
                    del route[sid]
                    removed += 1
                    sess = self.sessions.get(sid)
                    if sess is not None:
                        sess["routes"].discard(route_id)
            if not route:
                del self.routes[route_id]
        return removed

    def prune_stale_sessions(self) -> list[str]:
        now = time.monotonic()
        stale = [
            sid for sid, sess in self.sessions.items()
            if now - sess["last_heartbeat"] > self.config.session_stale_seconds
        ]
        for sid in stale:
            self.remove_session(sid)
        return stale

    # ── Dedupe (network plan §29) ─────────────────────────────────────────

    def check_and_mark_seen(self, dedupe_key: str, ttl_seconds: float) -> bool:
        now = time.monotonic()
        expires_at = self._seen.get(dedupe_key)
        if expires_at is not None and expires_at > now:
            return False
        self._seen[dedupe_key] = now + ttl_seconds
        return True

    def prune_dedupe(self) -> int:
        now = time.monotonic()
        stale_keys = [k for k, expires_at in self._seen.items() if expires_at <= now]
        for k in stale_keys:
            del self._seen[k]
        return len(stale_keys)
