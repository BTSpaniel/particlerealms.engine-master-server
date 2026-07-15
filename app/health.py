# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/health.py — GET /healthz, GET /readyz (network plan §7).
Clients do not poll these; an external monitor can check every 30-60s.
"""

from fastapi import APIRouter, Response

from .config import Config
from .hub import Hub


def create_health_router(hub: Hub, config: Config) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz():
        return Response(status_code=204)

    @router.get("/readyz")
    async def readyz():
        if hub.session_count() >= config.max_concurrency:
            return Response(status_code=503)
        return Response(status_code=204)

    return router
