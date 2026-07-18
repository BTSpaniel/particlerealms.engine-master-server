# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/health.py — GET /healthz, GET /readyz (network plan §7).
Clients do not poll these; an external monitor can check every 30-60s.
"""

import time

from fastapi import APIRouter, Response

from .config import Config
from .hub import Hub
from .metrics import Metrics


def readiness_reasons(hub: Hub, config: Config, metrics: Metrics, trust=None, node_mesh=None) -> list[str]:
    reasons: list[str] = []
    if hub.session_count() >= config.max_concurrency:
        reasons.append("session-capacity")
    if trust is not None and int(time.time()) > config.signing_key_expires_at:
        reasons.append("signing-key-expired")
    lag_p99 = metrics.quantile("event_loop_lag_seconds", 0.99)
    if lag_p99 > config.readiness_event_loop_p99_seconds:
        reasons.append("event-loop-lag")
    if metrics.gauge_value("process_rss_bytes") > config.readiness_rss_bytes:
        reasons.append("memory-pressure")
    if config.readiness_require_turn and not _turn_configured(config):
        reasons.append("turn-unavailable")
    if config.node_mesh_enabled and node_mesh is not None and not node_mesh.has_quorum():
        reasons.append("node-quorum")
    if (
        config.node_mesh_enabled
        and metrics.gauge_value("node_mesh_clock_skew_seconds") > config.node_mesh_max_clock_skew_seconds
    ):
        reasons.append("node-clock-skew")
    return reasons


def _turn_configured(config: Config) -> bool:
    return bool(
        config.turn_shared_secret
        or config.turn_shared_secrets_json.strip() not in {"", "[]"}
        or config.turn_servers_json.strip() not in {"", "[]"}
    )


def create_health_router(hub: Hub, config: Config, metrics: Metrics, trust=None, node_mesh=None) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz():
        return Response(status_code=204)

    @router.get("/readyz")
    async def readyz():
        if readiness_reasons(hub, config, metrics, trust, node_mesh):
            return Response(status_code=503)
        return Response(status_code=204)

    return router
