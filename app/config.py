# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/config.py — runtime configuration, all overridable via
environment variables so a self-hoster never has to edit source (network
plan §43: "self-hostable interface for others").

No secrets live here. No database connection strings either — this server
is intentionally in-memory only (network plan §6/§43 no-logging policy).
"""

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Config:
    # Anti-DoS limits (network plan §35)
    max_frame_bytes: int = _env_int("PARTICLE_MAX_FRAME_BYTES", 65536)
    max_routes_per_session: int = _env_int("PARTICLE_MAX_ROUTES_PER_SESSION", 8)
    max_subscriptions: int = _env_int("PARTICLE_MAX_SUBSCRIPTIONS", 16)
    max_fanout: int = _env_int("PARTICLE_MAX_FANOUT", 16)
    max_hops: int = _env_int("PARTICLE_MAX_HOPS", 3)
    max_concurrency: int = _env_int("PARTICLE_MAX_CONCURRENCY", 128)

    # Lifecycle timings (network plan §8/§9)
    route_lease_seconds: float = _env_float("PARTICLE_ROUTE_LEASE_SECONDS", 90.0)
    heartbeat_interval_seconds: float = _env_float("PARTICLE_HEARTBEAT_INTERVAL_SECONDS", 27.0)
    session_stale_seconds: float = _env_float("PARTICLE_SESSION_STALE_SECONDS", 90.0)
    dedupe_window_seconds: float = _env_float("PARTICLE_DEDUPE_WINDOW_SECONDS", 120.0)
    proof_deadline_seconds: float = _env_float("PARTICLE_PROOF_DEADLINE_SECONDS", 5.0)
    cleanup_interval_seconds: float = _env_float("PARTICLE_CLEANUP_INTERVAL_SECONDS", 15.0)


config = Config()
