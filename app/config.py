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
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class Config:
    # Anti-DoS limits (network plan §35)
    max_frame_bytes: int = _env_int("PARTICLE_MAX_FRAME_BYTES", 65536)
    max_routes_per_session: int = _env_int("PARTICLE_MAX_ROUTES_PER_SESSION", 32)
    max_v1_routes_per_session: int = _env_int("PARTICLE_MAX_V1_ROUTES_PER_SESSION", 8)
    max_subscriptions: int = _env_int("PARTICLE_MAX_SUBSCRIPTIONS", 16)
    max_fanout: int = _env_int("PARTICLE_MAX_FANOUT", 16)
    max_hops: int = _env_int("PARTICLE_MAX_HOPS", 3)
    max_concurrency: int = _env_int("PARTICLE_MAX_CONCURRENCY", 128)
    max_json_depth: int = _env_int("PARTICLE_MAX_JSON_DEPTH", 16)
    max_json_nodes: int = _env_int("PARTICLE_MAX_JSON_NODES", 512)
    max_dedupe_entries: int = _env_int("PARTICLE_MAX_DEDUPE_ENTRIES", 65536)
    admission_crypto_concurrency: int = _env_int("PARTICLE_ADMISSION_CRYPTO_CONCURRENCY", 8)
    admission_crypto_wait_seconds: float = _env_float("PARTICLE_ADMISSION_CRYPTO_WAIT_SECONDS", 0.25)
    # A 128-request per-address burst permits the controlled Pi gate to admit
    # clients behind one NAT. The sustained per-address and global buckets
    # still bound repeated public-key validation and grant-signing work.
    admission_rate_burst: int = _env_int("PARTICLE_ADMISSION_RATE_BURST", 128)
    admission_rate_per_second: float = _env_float("PARTICLE_ADMISSION_RATE_PER_SECOND", 2.0)
    admission_global_burst: int = _env_int("PARTICLE_ADMISSION_GLOBAL_BURST", 256)
    admission_global_per_second: float = _env_float("PARTICLE_ADMISSION_GLOBAL_PER_SECOND", 32.0)
    turn_rate_burst: int = _env_int("PARTICLE_TURN_RATE_BURST", 20)
    turn_rate_per_second: float = _env_float("PARTICLE_TURN_RATE_PER_SECOND", 1.0)
    turn_global_burst: int = _env_int("PARTICLE_TURN_GLOBAL_BURST", 128)
    turn_global_per_second: float = _env_float("PARTICLE_TURN_GLOBAL_PER_SECOND", 16.0)
    signal_global_burst: int = _env_int("PARTICLE_SIGNAL_GLOBAL_BURST", 512)
    signal_global_per_second: float = _env_float("PARTICLE_SIGNAL_GLOBAL_PER_SECOND", 256.0)
    message_global_burst: int = _env_int("PARTICLE_MESSAGE_GLOBAL_BURST", 2048)
    message_global_per_second: float = _env_float("PARTICLE_MESSAGE_GLOBAL_PER_SECOND", 1024.0)

    # Lifecycle timings (network plan §8/§9)
    route_lease_seconds: float = _env_float("PARTICLE_ROUTE_LEASE_SECONDS", 90.0)
    heartbeat_interval_seconds: float = _env_float("PARTICLE_HEARTBEAT_INTERVAL_SECONDS", 27.0)
    session_stale_seconds: float = _env_float("PARTICLE_SESSION_STALE_SECONDS", 90.0)
    dedupe_window_seconds: float = _env_float("PARTICLE_DEDUPE_WINDOW_SECONDS", 120.0)
    proof_deadline_seconds: float = _env_float("PARTICLE_PROOF_DEADLINE_SECONDS", 10.0)
    cleanup_interval_seconds: float = _env_float("PARTICLE_CLEANUP_INTERVAL_SECONDS", 15.0)

    # Bounded per-session delivery. Queues are intentionally small so a slow
    # recipient is removed instead of turning into global buffer pressure.
    outbound_queue_frames: int = _env_int("PARTICLE_OUTBOUND_QUEUE_FRAMES", 64)
    outbound_queue_bytes: int = _env_int("PARTICLE_OUTBOUND_QUEUE_BYTES", 262144)
    outbound_send_timeout_seconds: float = _env_float("PARTICLE_OUTBOUND_SEND_TIMEOUT_SECONDS", 5.0)

    # Signed v2 node identity and endpoint advertisement. The PEM can be
    # supplied inline or through PARTICLE_SIGNING_KEY_FILE. Development uses
    # one process-ephemeral key; production can require configured key material.
    node_id: str = os.environ.get("PARTICLE_NODE_ID", "particle-node-local")
    public_base_url: str = os.environ.get("PARTICLE_PUBLIC_BASE_URL", "http://127.0.0.1:8080")
    public_ws_url: str = os.environ.get("PARTICLE_PUBLIC_WS_URL", "ws://127.0.0.1:8080/v2/ws")
    public_v1_ws_url: str = os.environ.get("PARTICLE_PUBLIC_V1_WS_URL", "ws://127.0.0.1:8080/v1/ws")
    public_node_ws_url: str = os.environ.get("PARTICLE_PUBLIC_NODE_WS_URL", "ws://127.0.0.1:8080/v2/node")
    advertise_v2: bool = _env_bool("PARTICLE_ADVERTISE_V2", True)
    network_root_id: str = os.environ.get("PARTICLE_NETWORK_ROOT_ID", "particle-network-root-v1")
    network_root_version: int = _env_int("PARTICLE_NETWORK_ROOT_VERSION", 1)
    network_root_rollback_version: int = _env_int("PARTICLE_NETWORK_ROOT_ROLLBACK_VERSION", 0)
    signing_key_pem: str = os.environ.get("PARTICLE_SIGNING_KEY_PEM", "")
    signing_key_file: str = os.environ.get("PARTICLE_SIGNING_KEY_FILE", "")
    require_configured_signing_key: bool = _env_bool("PARTICLE_REQUIRE_CONFIGURED_SIGNING_KEY", False)
    signing_key_activates_at: int = _env_int("PARTICLE_SIGNING_KEY_ACTIVATES_AT", 0)
    signing_key_expires_at: int = _env_int("PARTICLE_SIGNING_KEY_EXPIRES_AT", 2147483647)
    manifest_ttl_seconds: int = _env_int("PARTICLE_MANIFEST_TTL_SECONDS", 3600)
    admission_ttl_seconds: int = _env_int("PARTICLE_ADMISSION_TTL_SECONDS", 60)

    # TURN REST credentials are derived per admitted identity when a shared
    # secret and URL list are configured. Static JSON remains available for
    # deployments whose TURN provider rotates credentials out of band.
    turn_servers_json: str = os.environ.get("PARTICLE_TURN_SERVERS_JSON", "[]")
    turn_urls_json: str = os.environ.get("PARTICLE_TURN_URLS_JSON", "[]")
    turn_shared_secret: str = os.environ.get("PARTICLE_TURN_SHARED_SECRET", "")
    turn_shared_secrets_json: str = os.environ.get("PARTICLE_TURN_SHARED_SECRETS_JSON", "[]")
    turn_username_prefix: str = os.environ.get("PARTICLE_TURN_USERNAME_PREFIX", "particle")
    turn_ttl_seconds: int = _env_int("PARTICLE_TURN_TTL_SECONDS", 600)

    # /metrics is loopback-only unless this bearer token is supplied.
    metrics_token: str = os.environ.get("PARTICLE_METRICS_TOKEN", "")
    allowed_origins_json: str = os.environ.get(
        "PARTICLE_ALLOWED_ORIGINS_JSON",
        '["https://particlerealms.online","http://127.0.0.1:9001","http://localhost:9001"]',
    )

    # Particle-native trusted-node mesh. JSON is a list of
    # {nodeId,url,serverKeyPin}; eight nodes is the first protocol ceiling.
    trusted_nodes_json: str = os.environ.get("PARTICLE_TRUSTED_NODES_JSON", "[]")
    node_mesh_enabled: bool = _env_bool("PARTICLE_NODE_MESH_ENABLED", False)
    node_mesh_replica_count: int = _env_int("PARTICLE_NODE_MESH_REPLICA_COUNT", 2)
    node_mesh_ack_timeout_seconds: float = _env_float("PARTICLE_NODE_MESH_ACK_TIMEOUT_SECONDS", 2.0)
    node_mesh_membership_epoch: int = _env_int("PARTICLE_NODE_MESH_MEMBERSHIP_EPOCH", 1)
    node_mesh_suspicion_seconds: float = _env_float("PARTICLE_NODE_MESH_SUSPICION_SECONDS", 10.0)
    node_mesh_max_clock_skew_seconds: float = _env_float("PARTICLE_NODE_MESH_MAX_CLOCK_SKEW_SECONDS", 30.0)
    node_mesh_max_pending_operations: int = _env_int("PARTICLE_NODE_MESH_MAX_PENDING_OPERATIONS", 1024)
    node_mesh_max_route_descriptors: int = _env_int("PARTICLE_NODE_MESH_MAX_ROUTE_DESCRIPTORS", 16384)
    node_mesh_ca_file: str = os.environ.get("PARTICLE_NODE_MESH_CA_FILE", "")
    node_mesh_cert_file: str = os.environ.get("PARTICLE_NODE_MESH_CERT_FILE", "")
    node_mesh_key_file: str = os.environ.get("PARTICLE_NODE_MESH_KEY_FILE", "")
    node_mesh_require_mtls: bool = _env_bool("PARTICLE_NODE_MESH_REQUIRE_MTLS", True)
    node_mesh_client_verify_header: str = os.environ.get(
        "PARTICLE_NODE_MESH_CLIENT_VERIFY_HEADER", "x-ssl-client-verify",
    )
    node_mesh_client_verify_value: str = os.environ.get(
        "PARTICLE_NODE_MESH_CLIENT_VERIFY_VALUE", "SUCCESS",
    )
    node_mesh_proxy_token_header: str = os.environ.get(
        "PARTICLE_NODE_MESH_PROXY_TOKEN_HEADER", "x-particle-node-proxy-token",
    )
    node_mesh_proxy_token: str = os.environ.get("PARTICLE_NODE_MESH_PROXY_TOKEN", "")

    runtime_metrics_interval_seconds: float = _env_float("PARTICLE_RUNTIME_METRICS_INTERVAL_SECONDS", 1.0)
    readiness_event_loop_p99_seconds: float = _env_float("PARTICLE_READINESS_EVENT_LOOP_P99_SECONDS", 0.25)
    readiness_rss_bytes: int = _env_int("PARTICLE_READINESS_RSS_BYTES", 600 * 1024 * 1024)
    readiness_require_turn: bool = _env_bool("PARTICLE_READINESS_REQUIRE_TURN", False)

    def __post_init__(self) -> None:
        bounded = {
            "max_frame_bytes": (1024, 1024 * 1024),
            "max_routes_per_session": (1, 256),
            "max_v1_routes_per_session": (1, 64),
            "max_subscriptions": (1, 256),
            "max_fanout": (1, 256),
            "max_hops": (1, 16),
            "max_concurrency": (1, 100_000),
            "max_json_depth": (2, 64),
            "max_json_nodes": (16, 100_000),
            "max_dedupe_entries": (1024, 10_000_000),
            "admission_crypto_concurrency": (1, 64),
            "admission_rate_burst": (1, 100_000),
            "admission_global_burst": (1, 100_000),
            "turn_rate_burst": (1, 100_000),
            "turn_global_burst": (1, 100_000),
            "signal_global_burst": (1, 100_000),
            "message_global_burst": (1, 1_000_000),
            "outbound_queue_frames": (1, 1024),
            "outbound_queue_bytes": (1024, 64 * 1024 * 1024),
            "network_root_version": (0, 2**31 - 1),
            "network_root_rollback_version": (0, 2**31 - 1),
            "manifest_ttl_seconds": (60, 86_400),
            "admission_ttl_seconds": (10, 3600),
            "turn_ttl_seconds": (60, 86_400),
            "node_mesh_replica_count": (1, 8),
            "node_mesh_membership_epoch": (1, 2**31 - 1),
            "node_mesh_max_pending_operations": (1, 100_000),
            "node_mesh_max_route_descriptors": (128, 1_000_000),
            "readiness_rss_bytes": (16 * 1024 * 1024, 64 * 1024 * 1024 * 1024),
        }
        for name, (minimum, maximum) in bounded.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be in {minimum}..{maximum}")
        positive = (
            "route_lease_seconds", "heartbeat_interval_seconds", "session_stale_seconds",
            "dedupe_window_seconds", "proof_deadline_seconds", "cleanup_interval_seconds",
            "admission_crypto_wait_seconds", "node_mesh_ack_timeout_seconds",
            "runtime_metrics_interval_seconds", "readiness_event_loop_p99_seconds",
            "admission_rate_per_second", "admission_global_per_second",
            "turn_rate_per_second", "turn_global_per_second",
            "signal_global_per_second", "outbound_send_timeout_seconds",
            "message_global_per_second",
        )
        for name in positive:
            value = getattr(self, name)
            if not 0 < value <= 86_400:
                raise ValueError(f"{name} must be finite and in 0..86400")
        for name in ("node_mesh_suspicion_seconds", "node_mesh_max_clock_skew_seconds"):
            value = getattr(self, name)
            if not 0 <= value <= 86_400:
                raise ValueError(f"{name} must be finite and in 0..86400")
        if self.outbound_queue_bytes < self.max_frame_bytes:
            raise ValueError("outbound_queue_bytes must hold at least one maximum-sized frame")
        if self.route_lease_seconds <= self.heartbeat_interval_seconds:
            raise ValueError("route_lease_seconds must exceed heartbeat_interval_seconds")
        if self.session_stale_seconds <= self.heartbeat_interval_seconds:
            raise ValueError("session_stale_seconds must exceed heartbeat_interval_seconds")
        if self.network_root_rollback_version > self.network_root_version:
            raise ValueError("network_root_rollback_version cannot exceed network_root_version")
        if self.signing_key_activates_at > self.signing_key_expires_at:
            raise ValueError("signing key activation cannot be after expiry")
        if not 1 <= len(self.node_id.encode("utf-8")) <= 128:
            raise ValueError("node_id must contain 1..128 UTF-8 bytes")
        if not 1 <= len(self.network_root_id.encode("utf-8")) <= 128:
            raise ValueError("network_root_id must contain 1..128 UTF-8 bytes")


config = Config()
