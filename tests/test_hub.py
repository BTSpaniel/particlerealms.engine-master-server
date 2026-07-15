# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import time

from app.config import Config
from app.hub import Hub


def make_hub(**overrides) -> Hub:
    cfg = Config(**overrides)
    return Hub(cfg)


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send_json(self, data):
        self.sent.append(data)


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
    hub = make_hub(session_stale_seconds=0.01)
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


def test_rate_limiter_blocks_after_capacity_exhausted():
    hub = make_hub()
    sid = hub.create_session(FakeWebSocket())
    allowed = [hub.rate_limiter.check(sid, "ATTACH_ROUTE") for _ in range(5)]
    assert allowed == [True, True, True, True, False]  # capacity 4/minute
