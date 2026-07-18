# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_reference_edge_has_finite_dos_boundaries():
    nginx = (ROOT / "nginx" / "particle-masterserver.conf.example").read_text(encoding="utf-8")
    for directive in (
        "limit_conn_zone $binary_remote_addr",
        "limit_conn particle_per_ip 160",
        "limit_conn particle_total 256",
        "limit_req zone=particle_general burst=384 nodelay",
        "limit_req zone=particle_sensitive burst=128 nodelay",
        "client_header_timeout 10s",
        "client_body_timeout 10s",
        "client_max_body_size 64k",
        "proxy_connect_timeout 3s",
        "reset_timedout_connection on",
        "keepalive_requests 100",
        "listen 443 ssl;",
        "access_log off",
        "server_name node-discovery.example.com",
        "ssl_verify_client on",
        "proxy_set_header X-Particle-Node-Proxy-Token replace-with-a-random-proxy-attestation-token",
    ):
        assert directive in nginx


def test_launchers_bound_backlog_and_service_resources():
    for relative in ("start.sh", "start.bat", "systemd/particle-masterserver.service"):
        launcher = (ROOT / relative).read_text(encoding="utf-8")
        assert "--backlog 256" in launcher
        assert "--forwarded-allow-ips 127.0.0.1" in launcher
    service = (ROOT / "systemd" / "particle-masterserver.service").read_text(encoding="utf-8")
    assert "LimitNOFILE=1024" in service
    assert "MemoryMax=640M" in service
    assert "MemorySwapMax=256M" in service
    assert "CapabilityBoundingSet=" in service
    assert "ProtectProc=invisible" in service
    assert "RestrictRealtime=true" in service


def test_public_tunnel_cannot_reach_the_node_mesh_endpoint():
    tunnel = (ROOT / "cloudflared" / "config.yml.example").read_text(encoding="utf-8")
    node_block = "path: ^/v2/node$\n    service: http_status:404"
    assert node_block in tunnel
    assert tunnel.index(node_block) < tunnel.index("service: http://127.0.0.1:8080")


def test_coturn_reference_has_allocation_bandwidth_and_peer_network_limits():
    coturn = (ROOT / "coturn" / "turnserver.conf.example").read_text(encoding="utf-8")
    for directive in (
        "use-auth-secret",
        "stale-nonce=600",
        "user-quota=4",
        "total-quota=128",
        "max-bps=2000000",
        "bps-capacity=64000000",
        "max-allocate-timeout=10",
        "min-port=49152",
        "max-port=49407",
        "no-tcp-relay",
        "no-rfc5780",
        "no-multicast-peers",
        "no-cli",
        "denied-peer-ip=10.0.0.0-10.255.255.255",
        "denied-peer-ip=192.168.0.0-192.168.255.255",
        "denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ):
        assert directive in coturn
    assert "server-relay\n" not in coturn
    assert "allow-loopback-peers\n" not in coturn
