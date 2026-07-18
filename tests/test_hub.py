# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import asyncio
import time

from app.config import Config
from app.hub import Hub
from app.ws_io import send_json_frame


def make_hub(**overrides) -> Hub:
    cfg = Config(**overrides)
    return Hub(cfg)


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self, code, reason):
        self.closed = (code, reason)


def test_attach_route_creates_route_and_lists_subscribers():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "route-1")
    assert hub.route_subscribers("route-1") == [sid]


def test_attach_route_enforces_max_routes_per_session():
    hub = make_hub(max_routes_per_session=2)
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "r1")
    hub.attach_route(sid, "r2")
    try:
        hub.attach_route(sid, "r3")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_detach_route_removes_subscriber_and_empties_route():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "route-1")
    hub.detach_route(sid, "route-1")
    assert hub.route_subscribers("route-1") == []
    assert "route-1" not in hub.routes


def test_heartbeat_route_extends_lease_only_for_attached_session():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "route-1", ttl_seconds=1000)
    assert hub.heartbeat_route(sid, "route-1", ttl_seconds=2000) is True
    assert hub.heartbeat_route("other-session", "route-1") is False


def test_prune_routes_removes_expired_leases():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "route-1", ttl_seconds=-1)  # already expired
    removed = hub.prune_routes()
    assert removed == 1
    assert "route-1" not in hub.routes


def test_remove_session_detaches_all_its_routes():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    hub.attach_route(sid, "route-1")
    hub.attach_route(sid, "route-2")
    hub.remove_session(sid)
    assert hub.route_subscribers("route-1") == []
    assert hub.route_subscribers("route-2") == []
    assert sid not in hub.sessions


def test_prune_stale_sessions_removes_sessions_past_the_stale_window():
    hub = make_hub(heartbeat_interval_seconds=0.001, session_stale_seconds=0.01)
    sid = hub.create_session(FakeWebSocket())
    hub.sessions[sid]["last_heartbeat"] = time.monotonic() - 10
    stale = hub.prune_stale_sessions()
    assert stale == [sid]
    assert sid not in hub.sessions


def test_dedupe_check_and_mark_seen():
    hub = make_hub()
    assert hub.check_and_mark_seen("k1", 60.0) is True
    assert hub.check_and_mark_seen("k1", 60.0) is False  # duplicate within TTL


def test_prune_dedupe_removes_only_expired_entries():
    hub = make_hub()
    hub.check_and_mark_seen("fresh", 60.0)
    hub._seen["stale"] = time.monotonic() - 1  # force-expire
    removed = hub.prune_dedupe()
    assert removed == 1
    assert "fresh" in hub._seen
    assert "stale" not in hub._seen


def test_dedupe_cardinality_fails_closed_at_configured_capacity():
    hub = make_hub(max_dedupe_entries=1024)
    for index in range(1024):
        assert hub.check_and_mark_seen(f"key-{index}", 60.0) is True
    assert hub.check_and_mark_seen("overflow", 60.0) is False
    assert len(hub._seen) == 1024
    assert hub.metrics.snapshot()["counters"]["dedupe_capacity_rejections"] == 1


def test_stale_pruning_actively_closes_the_orphaned_socket():
    async def scenario():
        hub = make_hub(heartbeat_interval_seconds=0.001, session_stale_seconds=0.01)
        websocket = FakeWebSocket()
        sid = hub.create_session(websocket)
        hub.sessions[sid]["last_heartbeat"] = time.monotonic() - 10
        assert hub.prune_stale_sessions() == [sid]
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return websocket.closed

    assert asyncio.run(scenario()) == (1001, "stale session")


def test_rate_limiter_blocks_after_capacity_exhausted():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    allowed = [hub.rate_limiter.check(sid, "ATTACH_ROUTE") for _ in range(5)]
    assert allowed == [True, True, True, True, False]  # capacity 4/minute


def test_slow_client_queue_isolated_and_closed_with_1013():
    class SlowWebSocket:
        def __init__(self):
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.closed = None

        async def send_json(self, _data):
            self.started.set()
            await self.release.wait()

        async def close(self, code, reason):
            self.closed = (code, reason)

    async def scenario():
        hub = make_hub(max_frame_bytes=1024, outbound_queue_frames=1, outbound_queue_bytes=1024)
        websocket = SlowWebSocket()
        session_id = hub.create_session(websocket)
        assert await hub.send_session(session_id, {"type": "first"}) is True
        await asyncio.wait_for(websocket.started.wait(), timeout=1)
        assert await hub.send_session(session_id, {"type": "queued"}) is True
        assert await hub.send_session(session_id, {"type": "rejected"}) is False
        assert websocket.closed == (1013, "slow client")
        websocket.release.set()
        await asyncio.sleep(0)
        hub.remove_session(session_id)
        assert hub._outbound_queued_bytes == 0
        assert hub.metrics.gauge_value("outbound_queued_bytes") == 0

    asyncio.run(scenario())


def test_control_and_relay_writes_are_serialized_per_websocket():
    class ObservedWebSocket:
        def __init__(self):
            self.active = 0
            self.maximum_active = 0

        async def send_json(self, _data):
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            await asyncio.sleep(0.001)
            self.active -= 1

    async def scenario():
        websocket = ObservedWebSocket()
        await asyncio.gather(*(send_json_frame(websocket, {"index": index}) for index in range(20)))
        return websocket.maximum_active

    assert asyncio.run(scenario()) == 1


def test_control_send_timeout_closes_a_slow_socket():
    class BlockedWebSocket:
        def __init__(self):
            self.closed = None

        async def send_json(self, _data):
            await asyncio.Event().wait()

        async def close(self, code, reason):
            self.closed = (code, reason)

    async def scenario():
        hub = make_hub(outbound_send_timeout_seconds=0.01)
        websocket = BlockedWebSocket()
        hub.create_session(websocket)
        try:
            await send_json_frame(websocket, {"type": "blocked"})
        except Exception:
            pass
        return websocket.closed

    assert asyncio.run(scenario()) == (1013, "slow client")
