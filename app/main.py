# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/main.py — application factory (network plan §43).

No database. No access log (run uvicorn with --no-access-log; see
Masterserver/README.md). docs/redoc/openapi are disabled; the exact public
surface is pinned by ``tests/test_no_logging.py`` so an accidental FastAPI
route cannot silently expand it.
"""

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import config as default_config
from .health import create_health_router
from .hub import Hub
from .metrics import Metrics, runtime_metrics_loop
from .node_mesh import NodeMesh
from .routes import create_ws_router
from .trust import NodeTrust
from .v2 import create_v2_router


async def _cleanup_loop(hub: Hub, config) -> None:
    while True:
        await asyncio.sleep(config.cleanup_interval_seconds)
        hub.prune_routes()
        hub.prune_stale_sessions()
        hub.prune_dedupe()


def create_app(config=None) -> FastAPI:
    cfg = config or default_config
    app_metrics = Metrics()
    hub = Hub(cfg, app_metrics)
    trust = NodeTrust(cfg)
    node_mesh = NodeMesh(cfg, hub, trust, app_metrics)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        cleanup_task = asyncio.create_task(_cleanup_loop(hub, cfg))
        metrics_task = asyncio.create_task(runtime_metrics_loop(app_metrics, cfg.runtime_metrics_interval_seconds))
        await node_mesh.start()
        try:
            yield
        finally:
            await node_mesh.stop()
            cleanup_task.cancel()
            metrics_task.cancel()
            await asyncio.gather(cleanup_task, metrics_task, return_exceptions=True)

    app = FastAPI(
        title="Particle Masterserver",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.hub = hub
    app.state.config = cfg
    app.state.metrics = app_metrics
    app.state.trust = trust
    app.state.node_mesh = node_mesh
    try:
        allowed_origins = json.loads(cfg.allowed_origins_json)
    except json.JSONDecodeError as exc:
        raise ValueError("PARTICLE_ALLOWED_ORIGINS_JSON must be valid JSON") from exc
    if not isinstance(allowed_origins, list) or not all(isinstance(origin, str) for origin in allowed_origins):
        raise ValueError("PARTICLE_ALLOWED_ORIGINS_JSON must be a JSON string list")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type", "authorization"],
    )
    app.include_router(create_health_router(hub, cfg, app_metrics, trust, node_mesh))
    app.include_router(create_ws_router(hub, cfg))
    app.include_router(create_v2_router(hub, cfg, trust, app_metrics, node_mesh))
    return app


app = create_app()
