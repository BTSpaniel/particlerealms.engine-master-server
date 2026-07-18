# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import asyncio
import json
import time

from app.config import Config
from app.hub import Hub
from app.metrics import Metrics
from app.node_mesh import NodeMesh
from app.trust import NodeTrust


class _Socket:
    def __init__(self):
        self.messages = []

    async def send(self, value):
        self.messages.append(json.loads(value))

    async def close(self):
        self.closed = True
        return None


def _mesh(node_id: str):
    trusted = [value for value in [
        {"nodeId": "node-a", "url": "wss://a.example/v2/node", "serverKeyPin": "a" * 64},
        {"nodeId": "node-b", "url": "wss://b.example/v2/node", "serverKeyPin": "b" * 64},
        {"nodeId": "node-c", "url": "wss://c.example/v2/node", "serverKeyPin": "c" * 64},
    ] if value["nodeId"] != node_id]
    config = Config(
        node_id=node_id,
        trusted_nodes_json=json.dumps(trusted),
        node_mesh_enabled=True,
        node_mesh_require_mtls=False,
        node_mesh_replica_count=2,
        node_mesh_suspicion_seconds=0.0,
    )
    metrics = Metrics()
    return NodeMesh(config, Hub(config, metrics), NodeTrust(config), metrics)


def test_rendezvous_route_owners_are_deterministic_and_replicated():
    mesh = _mesh("node-a")
    mesh.connections = {"node-b": object(), "node-c": object()}
    first = mesh.owners_for("a" * 64)
    second = mesh.owners_for("a" * 64)
    assert first == second
    assert len(first) == 2
    assert set(first).issubset({"node-a", "node-b", "node-c"})


def test_rendezvous_ownership_rehashes_only_after_quorum_confirms_loss():
    async def run():
        mesh = _mesh("node-a")
        mesh.connections = {"node-b": object(), "node-c": object()}
        before = mesh.owners_for("b" * 64)
        mesh.connections.pop("node-b")
        mesh._peer_views["node-c"] = (
            mesh.config.node_mesh_membership_epoch, {"node-a", "node-c"}, time.monotonic(),
        )
        await mesh._reconcile_membership()
        return mesh, before, mesh.owners_for("b" * 64)

    mesh, before, after = asyncio.run(run())
    assert "node-b" not in after
    assert after == mesh.owners_for("b" * 64)
    assert set(after) == {"node-a", "node-c"}
    assert before != after or "node-b" not in before


def test_only_lexicographically_lower_node_initiates_each_pair():
    mesh = _mesh("node-b")
    assert [node.node_id for node in mesh.trusted.values() if mesh.config.node_id < node.node_id] == ["node-c"]


def test_duplicate_authenticated_node_connection_is_rejected_without_overwrite():
    async def run():
        mesh = _mesh("node-a")
        original = _Socket()
        duplicate = _Socket()
        assert await mesh._claim_connection("node-b", original) is True
        assert await mesh._claim_connection("node-b", duplicate) is False
        return mesh, original, duplicate

    mesh, original, duplicate = asyncio.run(run())
    assert mesh.connections["node-b"] is original
    assert getattr(original, "closed", False) is False
    assert duplicate.closed is True


def test_node_loss_re_registers_local_routes_on_new_replica():
    async def run():
        mesh = _mesh("node-a")
        socket_b = _Socket()
        socket_c = _Socket()
        mesh.connections = {"node-b": socket_b, "node-c": socket_c}
        session_id = mesh.hub.create_session(_Socket())
        mesh.hub.set_v2_identity(session_id, "04" + "22" * 64, "04" + "11" * 64)
        mesh.hub.sessions[session_id]["proven"] = True
        mesh.hub.attach_route(session_id, "d" * 64)
        mesh.connections.pop("node-b")
        mesh._peer_views["node-c"] = (
            mesh.config.node_mesh_membership_epoch, {"node-a", "node-c"}, time.monotonic(),
        )
        await mesh._topology_changed()
        return socket_c.messages

    messages = asyncio.run(run())
    registrations = [message for message in messages if message["type"] == "ROUTE_REGISTER"]
    assert registrations
    assert registrations[-1]["payload"]["routeTag"] == "d" * 64


def test_node_manifest_must_match_the_pinned_network_root_reference():
    remote_config = Config(node_id="node-b", network_root_id="root-b")
    remote_trust = NodeTrust(remote_config)
    trusted = json.dumps([{
        "nodeId": "node-b",
        "url": "wss://b.example/v2/node",
        "serverKeyPin": remote_trust.key_id,
    }])
    local_config = Config(node_id="node-a", network_root_id="root-a", trusted_nodes_json=trusted)
    metrics = Metrics()
    mesh = NodeMesh(local_config, Hub(local_config, metrics), NodeTrust(local_config), metrics)
    assert mesh._authenticate_hello({
        "protocol": "particle-node/1",
        "type": "NODE_HELLO",
        "id": "hello",
        "payload": {"manifest": remote_trust.manifest()},
    }) is None


def test_excessive_node_clock_skew_is_rejected_and_exposed_to_readiness_metrics():
    async def run():
        mesh = _mesh("node-a")
        message = mesh._message("NODE_STATE", {
            "nodeId": "node-b",
            "membershipEpoch": mesh.config.node_mesh_membership_epoch,
            "incarnation": "incarnation-b",
            "connectedNodeIds": ["node-a", "node-b"],
            "sentAt": int(time.time()) - 600,
        })
        await mesh._handle_message("node-b", _Socket(), message)
        return mesh

    mesh = asyncio.run(run())
    snapshot = mesh.metrics.snapshot()
    assert "node-b" not in mesh._peer_views
    assert snapshot["counters"]["node_mesh_clock_skew_rejections"] == 1
    assert snapshot["gauges"]["node_mesh_clock_skew_seconds"] >= 590


def test_enabled_mesh_requires_complete_mtls_configuration():
    mesh = _mesh("node-a")
    mesh.config = Config(
        node_id="node-a",
        node_mesh_enabled=True,
        node_mesh_require_mtls=True,
        node_mesh_proxy_token="p" * 32,
        trusted_nodes_json=json.dumps([{
            "nodeId": "node-b", "url": "wss://b.example/v2/node", "serverKeyPin": "b" * 64,
        }]),
    )
    try:
        asyncio.run(mesh.start())
        assert False, "expected mTLS configuration failure"
    except RuntimeError as error:
        assert "PARTICLE_NODE_MESH_" in str(error)


def test_enabled_mesh_requires_proxy_attestation_secret_with_mtls_files():
    mesh = _mesh("node-a")
    mesh.config = Config(
        node_id="node-a",
        node_mesh_enabled=True,
        node_mesh_require_mtls=True,
        node_mesh_ca_file="ca.pem",
        node_mesh_cert_file="client.pem",
        node_mesh_key_file="client-key.pem",
        trusted_nodes_json=json.dumps([{
            "nodeId": "node-b", "url": "wss://b.example/v2/node", "serverKeyPin": "b" * 64,
        }]),
    )
    try:
        asyncio.run(mesh.start())
        assert False, "expected proxy attestation configuration failure"
    except RuntimeError as error:
        assert "PARTICLE_NODE_MESH_PROXY_TOKEN" in str(error)


def test_remote_route_descriptor_registry_has_a_hard_capacity():
    mesh = _mesh("node-a")
    mesh.config = Config(
        node_id="node-a", node_mesh_require_mtls=False, node_mesh_max_route_descriptors=128,
    )
    for index in range(129):
        mesh._apply_route_message("ROUTE_REGISTER", f"{index:064x}", {
            "sessionId": f"session-{index}",
            "nodeId": "node-b",
            "identityKeyHex": "04" + "11" * 64,
            "encryptionKeyHex": "04" + "22" * 64,
            "keyId": "a" * 64,
            "expiresAt": int(time.time()) + 60,
        })
    assert mesh._route_descriptor_count == 128
    assert sum(len(route) for route in mesh._route_registry.values()) == 128
    assert mesh.metrics.snapshot()["counters"]["node_mesh_descriptor_capacity_rejections"] == 1


def test_remote_descriptors_cannot_outlive_a_lease_or_collide_with_local_sessions():
    mesh = _mesh("node-a")
    local_session = mesh.hub.create_session(_Socket())
    base = {
        "nodeId": "node-b",
        "encryptionKeyHex": "04" + "22" * 64,
        "keyId": "a" * 64,
    }
    mesh._apply_route_message("ROUTE_REGISTER", "a" * 64, {
        **base,
        "sessionId": "far-future",
        "expiresAt": int(time.time() + mesh.config.route_lease_seconds + 3600),
    })
    mesh._apply_route_message("ROUTE_REGISTER", "b" * 64, {
        **base,
        "sessionId": local_session,
        "expiresAt": int(time.time() + 60),
    })
    assert mesh._route_descriptor_count == 0
    assert not mesh._route_registry
    assert mesh.metrics.snapshot()["counters"]["node_mesh_descriptor_identity_rejections"] == 2


def test_descriptor_cache_rejects_cross_node_session_reassignment():
    mesh = _mesh("node-a")
    first = {
        "sessionId": "shared-session",
        "nodeId": "node-b",
        "encryptionKeyHex": "04" + "22" * 64,
        "keyId": "a" * 64,
        "expiresAt": int(time.time() + 60),
    }
    assert mesh._cache_descriptor(first) is True
    assert mesh._cache_descriptor({**first, "nodeId": "node-c"}) is False
    assert mesh._session_nodes["shared-session"] == "node-b"


def test_stop_cancels_pending_work_and_clears_ephemeral_mesh_state():
    async def run():
        mesh = _mesh("node-a")
        pending_query = asyncio.get_running_loop().create_future()
        pending_ack = asyncio.get_running_loop().create_future()
        mesh._pending_queries["query"] = pending_query
        mesh._pending_acks["ack"] = pending_ack
        mesh._apply_route_message("ROUTE_REGISTER", "f" * 64, {
            "sessionId": "remote-session",
            "nodeId": "node-b",
            "identityKeyHex": "04" + "11" * 64,
            "encryptionKeyHex": "04" + "22" * 64,
            "keyId": "a" * 64,
            "expiresAt": int(time.time()) + 60,
        })
        await mesh.stop()
        return mesh, pending_query, pending_ack

    mesh, pending_query, pending_ack = asyncio.run(run())
    assert pending_query.cancelled() and pending_ack.cancelled()
    assert not mesh._pending_queries and not mesh._pending_acks
    assert not mesh._route_registry and mesh._route_descriptor_count == 0
    assert not mesh._session_nodes and not mesh._descriptor_cache


def test_trusted_mesh_rejects_more_than_eight_total_nodes():
    trusted = [
        {"nodeId": f"node-{i}", "url": f"wss://{i}.example/v2/node", "serverKeyPin": f"{i:064x}"}
        for i in range(8)
    ]
    config = Config(node_id="local", trusted_nodes_json=json.dumps(trusted))
    try:
        NodeMesh(config, Hub(config), NodeTrust(config), Metrics())
        assert False, "expected configured node ceiling"
    except ValueError as error:
        assert "seven remote" in str(error)
