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

import asyncio
import hashlib
import json
import time
import uuid

from .config import Config
from .metrics import Metrics, metrics as default_metrics
from .rate_limits import RateLimiterRegistry, TokenBucket
from .ws_io import send_json_frame


class Hub:
    def __init__(self, config: Config, metrics: Metrics | None = None):
        self.config = config
        self.metrics = metrics or default_metrics
        self.sessions: dict[str, dict] = {}
        self.routes: dict[str, dict[str, float]] = {}
        self._seen: dict[str, float] = {}
        self._outbound_queued_bytes = 0
        self.rate_limiter = RateLimiterRegistry()
        self.global_message_limiter = TokenBucket(
            config.message_global_burst, config.message_global_per_second,
        )

    # ── Sessions ──────────────────────────────────────────────────────────

    def create_session(self, websocket) -> str:
        session_id = uuid.uuid4().hex
        if getattr(websocket, "_particle_send_lock", None) is None:
            setattr(websocket, "_particle_send_lock", asyncio.Lock())
        setattr(websocket, "_particle_send_timeout", self.config.outbound_send_timeout_seconds)
        self.sessions[session_id] = {
            "ws": websocket,
            "proven": False,
            "challenge": None,
            "public_key_raw": None,
            "identity_key_hex": None,
            "identity_key_id": None,
            "created_at": time.monotonic(),
            "last_heartbeat": time.monotonic(),
            "routes": set(),
            "encryption_key_hex": None,
            "encryption_key_id": None,
            "protocol_version": 1,
            "last_signal_sequence": -1,
            "outbound_queue": asyncio.Queue(maxsize=self.config.outbound_queue_frames),
            "outbound_bytes": 0,
            "writer_task": None,
        }
        self.metrics.increment("sessions_created")
        self.metrics.gauge("active_sessions", len(self.sessions))
        return session_id

    def remove_session(self, session_id: str) -> None:
        sess = self.sessions.pop(session_id, None)
        if not sess:
            return
        writer_task = sess.get("writer_task")
        if writer_task is not None:
            writer_task.cancel()
        self._outbound_queued_bytes = max(0, self._outbound_queued_bytes - sess["outbound_bytes"])
        sess["outbound_bytes"] = 0
        self.metrics.gauge("outbound_queued_bytes", self._outbound_queued_bytes)
        for route_id in list(sess["routes"]):
            self.detach_route(session_id, route_id)
        self.rate_limiter.drop_session(session_id)
        self.metrics.increment("sessions_removed")
        self.metrics.gauge("active_sessions", len(self.sessions))

    def touch_heartbeat(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if sess:
            sess["last_heartbeat"] = time.monotonic()

    def session_count(self) -> int:
        return len(self.sessions)

    def set_v2_identity(self, session_id: str, identity_key_hex: str, encryption_key_hex: str) -> None:
        sess = self.sessions[session_id]
        sess["protocol_version"] = 2
        sess["identity_key_hex"] = identity_key_hex
        sess["identity_key_id"] = hashlib.sha256(bytes.fromhex(identity_key_hex)).hexdigest()
        sess["encryption_key_hex"] = encryption_key_hex
        sess["encryption_key_id"] = hashlib.sha256(bytes.fromhex(encryption_key_hex)).hexdigest()

    def peer_descriptor(self, session_id: str) -> dict | None:
        sess = self.sessions.get(session_id)
        if not sess or not sess.get("proven") or sess.get("protocol_version") != 2:
            return None
        return {
            "sessionId": session_id,
            "encryptionKeyHex": sess["encryption_key_hex"],
            "keyId": sess["encryption_key_id"],
        }

    async def send_session(self, session_id: str, data: dict) -> bool:
        """Queue one bounded outbound message without blocking other peers."""
        sess = self.sessions.get(session_id)
        if sess is None:
            return False
        encoded_bytes = len(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        queue = sess["outbound_queue"]
        if queue.full() or sess["outbound_bytes"] + encoded_bytes > self.config.outbound_queue_bytes:
            self.metrics.increment("outbound_queue_rejections")
            self.metrics.gauge("outbound_queued_bytes", self._outbound_queued_bytes)
            try:
                await asyncio.wait_for(
                    sess["ws"].close(code=1013, reason="slow client"), timeout=1.0,
                )
            except Exception:
                pass
            return False
        queue.put_nowait((data, encoded_bytes))
        sess["outbound_bytes"] += encoded_bytes
        self._outbound_queued_bytes += encoded_bytes
        if sess["writer_task"] is None or sess["writer_task"].done():
            sess["writer_task"] = asyncio.create_task(self._writer_loop(session_id, sess))
        self.metrics.gauge("outbound_queued_bytes", self._outbound_queued_bytes)
        return True

    async def _writer_loop(self, session_id: str, sess: dict) -> None:
        queue = sess["outbound_queue"]
        try:
            while self.sessions.get(session_id) is sess:
                data, encoded_bytes = await queue.get()
                try:
                    await send_json_frame(sess["ws"], data)
                finally:
                    if self.sessions.get(session_id) is sess:
                        sess["outbound_bytes"] = max(0, sess["outbound_bytes"] - encoded_bytes)
                        self._outbound_queued_bytes = max(0, self._outbound_queued_bytes - encoded_bytes)
                    queue.task_done()
                    self.metrics.gauge("outbound_queued_bytes", self._outbound_queued_bytes)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.metrics.increment("outbound_writer_failures")

    # ── Routes (network plan §9) ──────────────────────────────────────────

    def attach_route(
        self,
        session_id: str,
        route_id: str,
        ttl_seconds: float | None = None,
        max_routes: int | None = None,
    ) -> None:
        sess = self.sessions.get(session_id)
        if sess is None:
            raise KeyError("unknown session")
        route_limit = self.config.max_routes_per_session if max_routes is None else max_routes
        if route_id not in sess["routes"] and len(sess["routes"]) >= route_limit:
            raise ValueError("too-many-routes")
        ttl = ttl_seconds if ttl_seconds is not None else self.config.route_lease_seconds
        route = self.routes.setdefault(route_id, {})
        route[session_id] = time.monotonic() + ttl
        sess["routes"].add(route_id)
        self.metrics.increment("route_attachments")
        self.metrics.gauge("active_routes", len(self.routes))

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
        self.metrics.increment("route_detachments")
        self.metrics.gauge("active_routes", len(self.routes))

    def route_subscribers(self, route_id: str, exclude: str | None = None) -> list[str]:
        route = self.routes.get(route_id)
        if not route:
            return []
        now = time.monotonic()
        return [sid for sid, expires_at in route.items() if expires_at > now and sid != exclude]

    def route_peer_descriptors(self, route_id: str, exclude: str | None = None) -> list[dict]:
        descriptors = []
        for session_id in self.route_subscribers(route_id, exclude=exclude):
            descriptor = self.peer_descriptor(session_id)
            if descriptor is not None:
                descriptors.append(descriptor)
        return descriptors

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
            websocket = self.sessions[sid]["ws"]
            self.remove_session(sid)
            try:
                asyncio.get_running_loop().create_task(_close_stale_socket(websocket))
            except RuntimeError:
                pass
        return stale

    # ── Dedupe (network plan §29) ─────────────────────────────────────────

    def check_and_mark_seen(self, dedupe_key: str, ttl_seconds: float) -> bool:
        now = time.monotonic()
        expires_at = self._seen.get(dedupe_key)
        if expires_at is not None and expires_at > now:
            return False
        if expires_at is None and len(self._seen) >= self.config.max_dedupe_entries:
            self.prune_dedupe()
            if len(self._seen) >= self.config.max_dedupe_entries:
                self.metrics.increment("dedupe_capacity_rejections")
                return False
        self._seen[dedupe_key] = now + ttl_seconds
        return True

    def prune_dedupe(self) -> int:
        now = time.monotonic()
        stale_keys = [k for k, expires_at in self._seen.items() if expires_at <= now]
        for k in stale_keys:
            del self._seen[k]
        return len(stale_keys)


async def _close_stale_socket(websocket) -> None:
    try:
        await asyncio.wait_for(websocket.close(code=1001, reason="stale session"), timeout=1.0)
    except Exception:
        pass
