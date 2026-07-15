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


def test_public_surface_is_exactly_healthz_readyz_and_ws():
    app = create_app(Config())
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    assert paths == {"/healthz", "/readyz", "/v1/ws"}, f"unexpected public surface: {paths}"


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
