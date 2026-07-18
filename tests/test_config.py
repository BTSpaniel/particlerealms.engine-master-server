# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import math

import pytest

from app.config import Config, _env_bool, _env_float, _env_int


@pytest.mark.parametrize("overrides", [
    {"outbound_queue_frames": 0},
    {"outbound_queue_bytes": -1},
    {"max_frame_bytes": 0},
    {"max_concurrency": -1},
    {"admission_rate_burst": 0},
    {"admission_rate_per_second": math.nan},
    {"admission_global_burst": 0},
    {"admission_global_per_second": math.inf},
    {"turn_rate_burst": 0},
    {"turn_rate_per_second": math.nan},
    {"turn_global_burst": 0},
    {"turn_global_per_second": math.inf},
    {"max_dedupe_entries": 0},
    {"signal_global_burst": 0},
    {"signal_global_per_second": math.inf},
    {"outbound_send_timeout_seconds": 0},
    {"message_global_burst": 0},
    {"message_global_per_second": math.inf},
    {"route_lease_seconds": math.nan},
    {"proof_deadline_seconds": math.inf},
    {"manifest_ttl_seconds": -1},
    {"node_mesh_replica_count": 9},
    {"node_mesh_max_pending_operations": 0},
    {"node_mesh_max_route_descriptors": 127},
    {"route_lease_seconds": 10, "heartbeat_interval_seconds": 20},
    {"network_root_version": 1, "network_root_rollback_version": 2},
    {"signing_key_activates_at": 200, "signing_key_expires_at": 100},
])
def test_unsafe_resource_and_lifecycle_limits_fail_fast(overrides):
    with pytest.raises(ValueError):
        Config(**overrides)


def test_outbound_byte_budget_must_hold_a_maximum_frame():
    with pytest.raises(ValueError, match="at least one maximum-sized frame"):
        Config(max_frame_bytes=65_536, outbound_queue_bytes=32_768)


def test_invalid_environment_values_do_not_silently_fall_back(monkeypatch):
    monkeypatch.setenv("PARTICLE_TEST_INT", "many")
    monkeypatch.setenv("PARTICLE_TEST_FLOAT", "fast")
    monkeypatch.setenv("PARTICLE_TEST_BOOL", "maybe")
    with pytest.raises(ValueError):
        _env_int("PARTICLE_TEST_INT", 1)
    with pytest.raises(ValueError):
        _env_float("PARTICLE_TEST_FLOAT", 1.0)
    with pytest.raises(ValueError):
        _env_bool("PARTICLE_TEST_BOOL", False)
