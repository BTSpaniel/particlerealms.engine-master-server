# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Verifies the no-logging / tiny-public-API invariants (network plan §5/§6/§43):
  - the only public HTTP/WS routes are /healthz, /readyz, /v1/ws
  - interactive docs (Swagger/ReDoc/OpenAPI) are disabled
  - the Hub never persists anything to disk (no DB handle, no file writes)
"""

import inspect

from app.config import Config
from app.hub import Hub
from app.main import create_app


def test_public_surface_is_exactly_versioned_particle_interfaces():
    app = create_app(Config())
    # FastAPI 0.139+ keeps included routers as lazy wrappers. Walk their
    # original router tables so this security invariant covers HTTP and WS
    # routes on both lazy and eagerly flattened FastAPI releases.
    def collect_paths(routes):
        paths = set()
        for route in routes:
            path = getattr(route, "path", None)
            if isinstance(path, str):
                paths.add(path)
            original = getattr(route, "original_router", None)
            if original is not None:
                paths.update(collect_paths(original.routes))
        return paths

    paths = collect_paths(app.router.routes)
    assert paths == {
        "/healthz", "/readyz", "/status", "/metrics", "/v1/ws",
        "/v2/manifest", "/v2/admission", "/v2/turn", "/v2/ws", "/v2/node",
    }, f"unexpected public surface: {paths}"


def test_interactive_docs_are_disabled():
    app = create_app(Config())
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_hub_has_no_file_or_database_handles():
    hub = Hub(Config())
    # The Hub's entire persistent state must be plain in-memory containers —
    # no db/session/connection/file attributes of any kind.
    forbidden_substrings = ("db", "sql", "file", "conn", "sqlite", "session_store")
    for name, value in vars(hub).items():
        lname = name.lower()
        if name in ("sessions",):
            continue  # in-memory dict of live sockets, not a "session store"
        assert not any(s in lname for s in forbidden_substrings), f"Hub.{name} looks like persistent storage"


def test_hub_source_has_no_disk_or_network_persistence_calls():
    source = inspect.getsource(Hub)
    for banned in ("open(", "sqlite3", "requests.", "urllib", "aiofiles"):
        assert banned not in source, f"Hub source unexpectedly references {banned!r}"
