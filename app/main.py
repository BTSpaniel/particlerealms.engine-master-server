# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/main.py — application factory (network plan §43).

No database. No access log (run uvicorn with --no-access-log; see
Masterserver/README.md). docs/redoc/openapi are disabled so the only public
surface is /healthz, /readyz, and /v1/ws, per the plan's "keep the public
API tiny" rule.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import config as default_config
from .health import create_health_router
from .hub import Hub
from .routes import create_ws_router


async def _cleanup_loop(hub: Hub, config) -> None:
    while True:
        await asyncio.sleep(config.cleanup_interval_seconds)
        hub.prune_routes()
        hub.prune_stale_sessions()
        hub.prune_dedupe()


def create_app(config=None) -> FastAPI:
    cfg = config or default_config
    hub = Hub(cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        cleanup_task = asyncio.create_task(_cleanup_loop(hub, cfg))
        try:
            yield
        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass

    app = FastAPI(
        title="Particle Masterserver",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.hub = hub
    app.state.config = cfg
    app.include_router(create_health_router(hub, cfg))
    app.include_router(create_ws_router(hub, cfg))
    return app


app = create_app()
