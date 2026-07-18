# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Particle-native trusted masterserver mesh (`particle-node/1`).

Node links are fully connected for the first eight-node deployment. Route
descriptors are placed only on rendezvous-hash primary/replica owners and
expire with the same lease as local attachments. Relayed signaling remains
opaque ciphertext. TLS client certificates are configured for outbound links;
the reverse proxy must enforce client certificates on inbound `/v2/node`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import time
import uuid
from dataclasses import dataclass
from itertools import islice

import websockets
from fastapi import WebSocket, WebSocketDisconnect

from .canonical import canonical_json_bytes
from .config import Config
from .hub import Hub
from .metrics import Metrics
from .protocol import PROTOCOL_VERSIONS, ProtocolError, validate_v2_message
from .rate_limits import TokenBucket
from .strict_json import StrictJsonError, loads_strict
from .trust import NodeTrust, parse_signed_manifest


@dataclass(frozen=True)
class TrustedNode:
    node_id: str
    url: str
    server_key_pin: str


class NodeMesh:
    def __init__(self, config: Config, hub: Hub, trust: NodeTrust, metrics: Metrics):
        self.config = config
        self.hub = hub
        self.trust = trust
        self.metrics = metrics
        self.trusted = self._parse_trusted_nodes(config.trusted_nodes_json)
        if config.node_id in self.trusted:
            raise ValueError("trusted node list must not include the local node ID")
        self.connections: dict[str, object] = {}
        self._tasks: list[asyncio.Task] = []
        self._stopping = False
        self._route_registry: dict[str, dict[tuple[str, str], dict]] = {}
        self._route_descriptor_count = 0
        self._session_nodes: dict[str, str] = {}
        self._descriptor_cache: dict[str, dict] = {}
        self._pending_queries: dict[str, asyncio.Future] = {}
        self._pending_acks: dict[str, asyncio.Future] = {}
        self._membership_nodes: set[str] = {config.node_id, *self.trusted}
        self._peer_views: dict[str, tuple[int, set[str], float]] = {}
        self._suspected_since: dict[str, float] = {}
        self._incarnation = uuid.uuid4().hex
        self._send_locks: dict[int, asyncio.Lock] = {}
        self._has_quorum = not config.node_mesh_enabled or len(self._membership_nodes) == 1
        self._started = False

    @staticmethod
    def _parse_trusted_nodes(raw: str) -> dict[str, TrustedNode]:
        try:
            values = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("PARTICLE_TRUSTED_NODES_JSON must be valid JSON") from exc
        if not isinstance(values, list) or len(values) > 7:
            raise ValueError("trusted node list must contain at most seven remote nodes")
        result: dict[str, TrustedNode] = {}
        for value in values:
            if not isinstance(value, dict):
                raise ValueError("each trusted node must be an object")
            node_id = value.get("nodeId")
            url = value.get("url")
            pin = value.get("serverKeyPin")
            if not all(isinstance(item, str) and item for item in (node_id, url, pin)) or len(pin) != 64:
                raise ValueError("trusted nodes require nodeId, url, and 64-character serverKeyPin")
            if node_id in result:
                raise ValueError("trusted node IDs must be unique")
            if not all(ch in "0123456789abcdefABCDEF" for ch in pin):
                raise ValueError("trusted node serverKeyPin must be hexadecimal")
            result[node_id] = TrustedNode(node_id=node_id, url=url, server_key_pin=pin.lower())
        return result

    async def start(self) -> None:
        if not self.config.node_mesh_enabled:
            return
        if self.config.node_mesh_require_mtls and len(self.config.node_mesh_proxy_token.encode("utf-8")) < 32:
            raise RuntimeError("PARTICLE_NODE_MESH_PROXY_TOKEN must contain at least 32 bytes")
        if self.trusted and self.config.node_mesh_require_mtls:
            if any(not node.url.lower().startswith("wss://") for node in self.trusted.values()):
                raise RuntimeError("node mesh mTLS requires wss:// for every trusted node")
            missing = [
                name for name, value in (
                    ("PARTICLE_NODE_MESH_CA_FILE", self.config.node_mesh_ca_file),
                    ("PARTICLE_NODE_MESH_CERT_FILE", self.config.node_mesh_cert_file),
                    ("PARTICLE_NODE_MESH_KEY_FILE", self.config.node_mesh_key_file),
                ) if not value
            ]
            if missing:
                raise RuntimeError(f"node mesh mTLS configuration is missing: {', '.join(missing)}")
        self._stopping = False
        self._started = True
        for node in self.trusted.values():
            # Exactly one side initiates each pair, preventing competing links.
            if self.config.node_id < node.node_id:
                self._tasks.append(asyncio.create_task(self._connect_forever(node)))
        self._tasks.append(asyncio.create_task(self._membership_loop()))
        self.metrics.gauge("node_mesh_configured_peers", len(self.trusted))

    async def stop(self) -> None:
        self._stopping = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        for connection in list(self.connections.values()):
            await _close_socket(connection)
        self.connections.clear()
        for future in (*self._pending_queries.values(), *self._pending_acks.values()):
            if not future.done():
                future.cancel()
        self._pending_queries.clear()
        self._pending_acks.clear()
        self._route_registry.clear()
        self._route_descriptor_count = 0
        self._session_nodes.clear()
        self._descriptor_cache.clear()
        self._peer_views.clear()
        self._suspected_since.clear()
        self._membership_nodes = self._membership_universe()
        self._has_quorum = not self.config.node_mesh_enabled or len(self._membership_nodes) == 1
        self._send_locks.clear()
        self._started = False
        self.metrics.gauge("node_mesh_connected_peers", 0)

    def owners_for(self, route_tag: str) -> list[str]:
        nodes = sorted(self._membership_nodes)
        count = min(max(1, self.config.node_mesh_replica_count), len(nodes))
        ranked = sorted(
            nodes,
            key=lambda node_id: hashlib.sha256(f"{route_tag}\0{node_id}".encode("utf-8")).digest(),
            reverse=True,
        )
        return ranked[:count]

    async def register_local_route(self, route_tag: str, session_id: str) -> None:
        descriptor = self.hub.peer_descriptor(session_id)
        if descriptor is None:
            return
        descriptor = {**descriptor, "nodeId": self.config.node_id, "expiresAt": int(time.time() + self.config.route_lease_seconds)}
        await self._replicate("ROUTE_REGISTER", route_tag, descriptor)

    async def remove_local_route(self, route_tag: str, session_id: str) -> None:
        descriptor = {"sessionId": session_id, "nodeId": self.config.node_id}
        await self._replicate("ROUTE_REMOVE", route_tag, descriptor)

    async def _replicate(self, msg_type: str, route_tag: str, descriptor: dict) -> None:
        sends = []
        for owner in self.owners_for(route_tag):
            if owner == self.config.node_id:
                self._apply_route_message(msg_type, route_tag, descriptor)
                continue
            connection = self.connections.get(owner)
            if connection is not None:
                sends.append(self._bounded_send(
                    connection, self._message(msg_type, {"routeTag": route_tag, "descriptor": descriptor}),
                ))
        if sends:
            results = await asyncio.gather(*sends, return_exceptions=True)
            self.metrics.increment("node_mesh_send_failures", sum(result is not True for result in results))

    async def discover(self, route_tag: str) -> list[dict]:
        self._prune_routes()
        descriptors: dict[str, dict] = {}
        for item in self._route_registry.get(route_tag, {}).values():
            if self._cache_descriptor(item):
                descriptors[item["sessionId"]] = item
        query_tasks = []
        for owner in self.owners_for(route_tag):
            if owner == self.config.node_id:
                continue
            connection = self.connections.get(owner)
            if connection is not None:
                query_tasks.append(self._query_owner(connection, route_tag))
        if query_tasks:
            results = await asyncio.gather(*query_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    for descriptor in result:
                        if self._cache_descriptor(descriptor):
                            descriptors[descriptor["sessionId"]] = descriptor
        return list(descriptors.values())

    async def forward_signal(self, route_tag: str, target_session_id: str, envelope: dict) -> bool:
        node_id = self._session_nodes.get(target_session_id)
        if not node_id or node_id == self.config.node_id:
            return False
        connection = self.connections.get(node_id)
        if connection is None:
            return False
        if self._pending_operation_count() >= self.config.node_mesh_max_pending_operations:
            self.metrics.increment("node_mesh_pending_capacity_rejections")
            return False
        request_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self._pending_acks[request_id] = future
        sent = await self._bounded_send(connection, self._message("SIGNAL_FORWARD", {
            "requestId": request_id,
            "routeTag": route_tag,
            "targetSessionId": target_session_id,
            "envelope": envelope,
        }))
        if not sent:
            self._pending_acks.pop(request_id, None)
            return False
        try:
            return bool(await asyncio.wait_for(future, timeout=self.config.node_mesh_ack_timeout_seconds))
        except asyncio.TimeoutError:
            self.metrics.increment("node_mesh_ack_timeouts")
            return False
        finally:
            self._pending_acks.pop(request_id, None)

    def remote_descriptor(self, target_session_id: str) -> dict | None:
        cached = self._descriptor_cache.get(target_session_id)
        if cached is not None and cached.get("expiresAt", 0) > int(time.time()):
            return cached
        if cached is not None:
            self._descriptor_cache.pop(target_session_id, None)
            self._session_nodes.pop(target_session_id, None)
        for route in self._route_registry.values():
            for descriptor in route.values():
                if descriptor.get("sessionId") == target_session_id:
                    return descriptor
        return None

    async def accept(self, websocket: WebSocket) -> None:
        # particle-node/1 is an envelope namespace, not an RFC 6455 token.
        await websocket.accept()
        try:
            raw_first = await asyncio.wait_for(_receive_text(websocket), timeout=self.config.proof_deadline_seconds)
            if len(raw_first.encode("utf-8")) > self.config.max_frame_bytes:
                await websocket.close(code=1009, reason="node hello too large")
                return
            first = loads_strict(
                raw_first, max_bytes=self.config.max_frame_bytes, max_depth=self.config.max_json_depth,
                max_nodes=self.config.max_json_nodes, max_string_bytes=self.config.max_frame_bytes,
            )
            node_id = self._authenticate_hello(first)
            if node_id is None or node_id >= self.config.node_id:
                await websocket.close(code=1008, reason="untrusted node")
                return
            await websocket.send_json(self._hello_message())
            if not await self._claim_connection(node_id, websocket):
                return
            await self._topology_changed()
            await self._bounded_send(websocket, self._state_message())
            await self._connection_loop(node_id, websocket)
        except (asyncio.TimeoutError, StrictJsonError, WebSocketDisconnect):
            return

    async def _connect_forever(self, node: TrustedNode) -> None:
        delay = 1.0
        while not self._stopping:
            try:
                async with websockets.connect(
                    node.url,
                    ssl=self._ssl_context(node.url),
                    max_size=self.config.max_frame_bytes,
                    max_queue=16,
                    open_timeout=10,
                    compression=None,
                ) as websocket:
                    await _send_json(websocket, self._hello_message())
                    response = loads_strict(
                        await asyncio.wait_for(websocket.recv(), timeout=self.config.proof_deadline_seconds),
                        max_bytes=self.config.max_frame_bytes, max_depth=self.config.max_json_depth,
                        max_nodes=self.config.max_json_nodes, max_string_bytes=self.config.max_frame_bytes,
                    )
                    node_id = self._authenticate_hello(response, expected_node=node)
                    if node_id is None:
                        raise RuntimeError("remote node manifest failed pin verification")
                    if not await self._claim_connection(node_id, websocket):
                        raise RuntimeError("duplicate trusted-node connection")
                    await self._topology_changed()
                    await self._bounded_send(websocket, self._state_message())
                    delay = 1.0
                    await self._connection_loop(node_id, websocket)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.metrics.increment("node_mesh_connection_failures")
            if not self._stopping:
                await asyncio.sleep(delay)
                delay = min(30.0, delay * 2.0)

    async def _connection_loop(self, node_id: str, websocket) -> None:
        self.metrics.gauge("node_mesh_connected_peers", len(self.connections))
        message_bucket = TokenBucket(400.0, 200.0)
        try:
            while True:
                raw = await _receive_text(websocket)
                if len(raw.encode("utf-8")) > self.config.max_frame_bytes or not message_bucket.try_consume():
                    self.metrics.increment("node_mesh_rate_or_size_rejections")
                    await _close_socket(websocket)
                    break
                data = loads_strict(
                    raw, max_bytes=self.config.max_frame_bytes, max_depth=self.config.max_json_depth,
                    max_nodes=self.config.max_json_nodes, max_string_bytes=self.config.max_frame_bytes,
                )
                if not _valid_node_envelope(data):
                    self.metrics.increment("node_mesh_protocol_rejections")
                    continue
                if not self.hub.check_and_mark_seen(
                    f"node:{node_id}:{data['id']}", self.config.dedupe_window_seconds,
                ):
                    self.metrics.increment("node_mesh_replay_rejections")
                    continue
                await self._handle_message(node_id, websocket, data)
        except (WebSocketDisconnect, StrictJsonError):
            pass
        finally:
            self._send_locks.pop(id(websocket), None)
            removed = self.connections.get(node_id) is websocket
            if removed:
                self.connections.pop(node_id, None)
                self._suspected_since.setdefault(node_id, time.monotonic())
            self.metrics.gauge("node_mesh_connected_peers", len(self.connections))
            if removed and not self._stopping:
                await self._topology_changed()

    async def _claim_connection(self, node_id: str, websocket) -> bool:
        existing = self.connections.get(node_id)
        if existing is not None and existing is not websocket:
            self.metrics.increment("node_mesh_duplicate_connection_rejections")
            await _close_socket(websocket)
            return False
        self.connections[node_id] = websocket
        return True

    def _authenticate_hello(self, message: dict, expected_node: TrustedNode | None = None) -> str | None:
        if not _valid_node_envelope(message) or message.get("type") != "NODE_HELLO":
            return None
        manifest = (message.get("payload") or {}).get("manifest")
        claimed_id = ((manifest or {}).get("payload") or {}).get("nodeId")
        trusted = expected_node or self.trusted.get(claimed_id)
        if trusted is None or trusted.node_id != claimed_id:
            return None
        valid, payload = parse_signed_manifest(manifest, trusted.server_key_pin)
        now = int(time.time())
        if (
            not valid
            or payload is None
            or payload.get("networkRootId") != self.config.network_root_id
            or payload.get("networkRootVersion") != self.config.network_root_version
            or payload.get("networkRootRollbackVersion") != self.config.network_root_rollback_version
            or not payload.get("issuedAt") <= now <= payload.get("expiresAt")
        ):
            return None
        return claimed_id

    async def _handle_message(self, node_id: str, websocket, message: dict) -> None:
        if message.get("protocol") != PROTOCOL_VERSIONS["NODE"] or not isinstance(message.get("payload"), dict):
            return
        msg_type = message.get("type")
        payload = message["payload"]
        if msg_type in {"ROUTE_REGISTER", "ROUTE_REMOVE"}:
            route_tag = payload.get("routeTag")
            descriptor = payload.get("descriptor")
            if (
                _valid_route_tag(route_tag)
                and self.config.node_id in self.owners_for(route_tag)
                and _valid_descriptor(descriptor, removal=msg_type == "ROUTE_REMOVE")
                and descriptor.get("nodeId") == node_id
                and (msg_type == "ROUTE_REMOVE" or self._descriptor_is_current(descriptor))
            ):
                self._apply_route_message(msg_type, route_tag, descriptor)
        elif msg_type == "ROUTE_QUERY":
            route_tag = payload.get("routeTag")
            query_id = payload.get("queryId")
            if _valid_route_tag(route_tag) and isinstance(query_id, str) and len(query_id) <= 64:
                self._prune_routes()
                descriptors = list(islice(
                    self._route_registry.get(route_tag, {}).values(), self.config.max_fanout,
                ))
                await self._bounded_send(
                    websocket, self._message("ROUTE_RESULT", {"queryId": query_id, "descriptors": descriptors}),
                )
        elif msg_type == "ROUTE_RESULT":
            future = self._pending_queries.get(payload.get("queryId"))
            if future is not None and not future.done():
                descriptors = payload.get("descriptors")
                future.set_result([
                    descriptor for descriptor in descriptors[: self.config.max_fanout]
                    if _valid_descriptor(descriptor) and self._descriptor_is_current(descriptor)
                ] if isinstance(descriptors, list) else [])
        elif msg_type == "SIGNAL_FORWARD":
            target = payload.get("targetSessionId")
            route_tag = payload.get("routeTag")
            envelope = payload.get("envelope")
            valid_envelope = False
            if isinstance(envelope, dict):
                try:
                    validate_v2_message(envelope)
                    signal_payload = envelope.get("payload") or {}
                    valid_envelope = (
                        envelope.get("type") == "SIGNAL"
                        and signal_payload.get("routeTag") == route_tag
                        and signal_payload.get("toSessionId") == target
                    )
                except ProtocolError:
                    valid_envelope = False
            delivered = bool(
                valid_envelope
                and isinstance(target, str)
                and isinstance(route_tag, str)
                and target in self.hub.route_subscribers(route_tag)
                and await self.hub.send_session(target, envelope)
            )
            await self._bounded_send(
                websocket, self._message("ACK", {"requestId": payload.get("requestId"), "delivered": delivered}),
            )
        elif msg_type == "ACK":
            future = self._pending_acks.get(payload.get("requestId"))
            if future is not None and not future.done():
                future.set_result(payload.get("delivered") is True)
        elif msg_type == "NODE_STATE":
            connected = payload.get("connectedNodeIds")
            epoch = payload.get("membershipEpoch")
            incarnation = payload.get("incarnation")
            sent_at = payload.get("sentAt")
            skew = abs(int(time.time()) - sent_at) if isinstance(sent_at, int) and not isinstance(sent_at, bool) else float("inf")
            if skew != float("inf"):
                self.metrics.gauge("node_mesh_clock_skew_seconds", skew)
            if (
                payload.get("nodeId") == node_id
                and epoch == self.config.node_mesh_membership_epoch
                and isinstance(incarnation, str) and 1 <= len(incarnation) <= 64
                and isinstance(connected, list) and len(connected) <= 8
                and all(isinstance(item, str) and item in self._membership_universe() for item in connected)
                and skew <= self.config.node_mesh_max_clock_skew_seconds
            ):
                self._peer_views[node_id] = (epoch, set(connected) | {node_id}, time.monotonic())
                self.metrics.increment("node_mesh_state_messages")
                await self._reconcile_membership()
            elif skew > self.config.node_mesh_max_clock_skew_seconds:
                self.metrics.increment("node_mesh_clock_skew_rejections")

    def _apply_route_message(self, msg_type: str, route_tag: str, descriptor: dict) -> None:
        session_id = descriptor.get("sessionId")
        node_id = descriptor.get("nodeId")
        if not isinstance(session_id, str) or not isinstance(node_id, str):
            return
        route = self._route_registry.get(route_tag)
        key = (node_id, session_id)
        if msg_type == "ROUTE_REMOVE":
            if route is None:
                return
            if route.pop(key, None) is not None:
                self._route_descriptor_count -= 1
        elif isinstance(descriptor.get("expiresAt"), int):
            current_node = self._session_nodes.get(session_id)
            if (
                not self._descriptor_is_current(descriptor)
                or (node_id != self.config.node_id and session_id in self.hub.sessions)
                or (current_node is not None and current_node != node_id)
            ):
                self.metrics.increment("node_mesh_descriptor_identity_rejections")
                return
            if route is None:
                route = {}
                self._route_registry[route_tag] = route
            if key not in route:
                if self._route_descriptor_count >= self.config.node_mesh_max_route_descriptors:
                    self.metrics.increment("node_mesh_descriptor_capacity_rejections")
                    if not route:
                        self._route_registry.pop(route_tag, None)
                    return
                self._route_descriptor_count += 1
            route[key] = descriptor
            self._session_nodes[session_id] = node_id
        if route is not None and not route:
            self._route_registry.pop(route_tag, None)

    async def _topology_changed(self) -> None:
        """Drop stale ownership and re-register every local lease after failover."""
        await self._reconcile_membership()
        active = {self.config.node_id, *self.connections}
        for route_tag in list(self._route_registry):
            if self.config.node_id not in self.owners_for(route_tag):
                self._route_descriptor_count -= len(self._route_registry.pop(route_tag, {}))
                continue
            route = self._route_registry[route_tag]
            for key, descriptor in list(route.items()):
                if descriptor.get("nodeId") not in active:
                    route.pop(key, None)
                    self._route_descriptor_count -= 1
            if not route:
                self._route_registry.pop(route_tag, None)
        for session_id, session in list(self.hub.sessions.items()):
            if session.get("proven") and session.get("protocol_version") == 2:
                for route_tag in list(session["routes"]):
                    await self.register_local_route(route_tag, session_id)
        self.metrics.increment("node_mesh_rebalances")

    async def _query_owner(self, connection, route_tag: str) -> list[dict]:
        if self._pending_operation_count() >= self.config.node_mesh_max_pending_operations:
            self.metrics.increment("node_mesh_pending_capacity_rejections")
            return []
        query_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self._pending_queries[query_id] = future
        if not await self._bounded_send(
            connection, self._message("ROUTE_QUERY", {"queryId": query_id, "routeTag": route_tag}),
        ):
            self._pending_queries.pop(query_id, None)
            return []
        try:
            return await asyncio.wait_for(future, timeout=self.config.node_mesh_ack_timeout_seconds)
        except asyncio.TimeoutError:
            return []
        finally:
            self._pending_queries.pop(query_id, None)

    def _prune_routes(self) -> None:
        now = int(time.time())
        for session_id, descriptor in list(self._descriptor_cache.items()):
            if descriptor.get("expiresAt", 0) <= now:
                self._descriptor_cache.pop(session_id, None)
                self._session_nodes.pop(session_id, None)
        for route_tag in list(self._route_registry):
            route = self._route_registry[route_tag]
            for key, descriptor in list(route.items()):
                if descriptor.get("expiresAt", 0) <= now:
                    route.pop(key, None)
                    self._route_descriptor_count -= 1
            if not route:
                self._route_registry.pop(route_tag, None)

    def _hello_message(self) -> dict:
        return self._message("NODE_HELLO", {"manifest": self.trust.manifest()})

    def _state_message(self) -> dict:
        return self._message("NODE_STATE", {
            "nodeId": self.config.node_id,
            "membershipEpoch": self.config.node_mesh_membership_epoch,
            "incarnation": self._incarnation,
            "connectedNodeIds": sorted({self.config.node_id, *self.connections}),
            "sentAt": int(time.time()),
        })

    def _message(self, msg_type: str, payload: dict) -> dict:
        return {
            "protocol": PROTOCOL_VERSIONS["NODE"],
            "type": msg_type,
            "id": uuid.uuid4().hex,
            "payload": payload,
        }

    async def _bounded_send(self, websocket, data: dict) -> bool:
        lock = self._send_locks.setdefault(id(websocket), asyncio.Lock())
        try:
            async with lock:
                await asyncio.wait_for(
                    _send_json(websocket, data),
                    timeout=self.config.node_mesh_ack_timeout_seconds,
                )
            return True
        except Exception:
            return False

    def _membership_universe(self) -> set[str]:
        return {self.config.node_id, *self.trusted}

    def _pending_operation_count(self) -> int:
        return len(self._pending_queries) + len(self._pending_acks)

    def _descriptor_is_current(self, descriptor: dict) -> bool:
        expires_at = descriptor.get("expiresAt")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            return False
        now = int(time.time())
        skew = self.config.node_mesh_max_clock_skew_seconds
        return now - skew < expires_at <= now + self.config.route_lease_seconds + skew

    def _cache_descriptor(self, descriptor: dict) -> bool:
        session_id = descriptor.get("sessionId")
        node_id = descriptor.get("nodeId")
        if not isinstance(session_id, str) or not isinstance(node_id, str) or not self._descriptor_is_current(descriptor):
            return False
        current_node = self._session_nodes.get(session_id)
        if (
            (node_id != self.config.node_id and session_id in self.hub.sessions)
            or (current_node is not None and current_node != node_id)
        ):
            self.metrics.increment("node_mesh_descriptor_identity_rejections")
            return False
        if session_id not in self._descriptor_cache and len(self._descriptor_cache) >= self.config.node_mesh_max_route_descriptors:
            self.metrics.increment("node_mesh_descriptor_capacity_rejections")
            return False
        self._session_nodes[session_id] = node_id
        self._descriptor_cache[session_id] = descriptor
        return True

    def has_quorum(self) -> bool:
        return self._has_quorum

    async def _membership_loop(self) -> None:
        interval = max(1.0, min(5.0, self.config.node_mesh_suspicion_seconds / 2.0))
        while not self._stopping:
            await asyncio.sleep(interval)
            await self._reconcile_membership()
            await asyncio.gather(
                *(self._bounded_send(connection, self._state_message()) for connection in self.connections.values()),
                return_exceptions=True,
            )

    async def _reconcile_membership(self) -> None:
        universe = self._membership_universe()
        quorum = len(universe) // 2 + 1
        now = time.monotonic()
        stale_after = max(3.0, self.config.node_mesh_suspicion_seconds * 3.0)
        reporters: dict[str, set[str]] = {
            self.config.node_id: {self.config.node_id, *self.connections},
        }
        for reporter, (epoch, view, received_at) in list(self._peer_views.items()):
            if epoch != self.config.node_mesh_membership_epoch or now - received_at > stale_after:
                self._peer_views.pop(reporter, None)
                continue
            reporters[reporter] = view & universe
        self._has_quorum = len(reporters) >= quorum
        self.metrics.gauge("node_mesh_membership_quorum", 1 if self._has_quorum else 0)
        self.metrics.gauge("node_mesh_membership_reporters", len(reporters))
        if not self._has_quorum:
            return
        next_members = set(self._membership_nodes)
        next_members.add(self.config.node_id)
        for candidate in universe - {self.config.node_id}:
            alive_votes = sum(candidate in view for view in reporters.values())
            if alive_votes >= quorum:
                next_members.add(candidate)
                self._suspected_since.pop(candidate, None)
                continue
            suspected = self._suspected_since.setdefault(candidate, now)
            if now - suspected >= self.config.node_mesh_suspicion_seconds:
                next_members.discard(candidate)
        if next_members != self._membership_nodes:
            self._membership_nodes = next_members
            self.metrics.increment("node_mesh_membership_changes")
            self.metrics.gauge("node_mesh_membership_nodes", len(next_members))

    def _ssl_context(self, url: str):
        if not url.lower().startswith("wss://"):
            return None
        context = ssl.create_default_context(cafile=self.config.node_mesh_ca_file or None)
        if self.config.node_mesh_cert_file and self.config.node_mesh_key_file:
            context.load_cert_chain(self.config.node_mesh_cert_file, self.config.node_mesh_key_file)
        return context


async def _send_json(websocket, data: dict) -> None:
    text = canonical_json_bytes(data).decode("utf-8")
    if hasattr(websocket, "send_text"):
        await websocket.send_text(text)
    else:
        await websocket.send(text)


async def _receive_text(websocket) -> str:
    if hasattr(websocket, "receive_text"):
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            raise WebSocketDisconnect(code=message.get("code", 1000))
        if not isinstance(message.get("text"), str):
            await websocket.close(code=1003, reason="text frames required")
            raise WebSocketDisconnect(code=1003)
        return message["text"]
    value = await websocket.recv()
    if not isinstance(value, str):
        await websocket.close(code=1003, reason="text frames required")
        raise ValueError("node mesh requires text frames")
    return value


async def _close_socket(websocket) -> None:
    try:
        await websocket.close()
    except Exception:
        pass


def _valid_route_tag(value) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _valid_descriptor(value, *, removal: bool = False) -> bool:
    expected = {"sessionId", "nodeId"} if removal else {
        "sessionId", "encryptionKeyHex", "keyId", "nodeId", "expiresAt",
    }
    if not isinstance(value, dict) or set(value) != expected:
        return False
    common = (
        isinstance(value["sessionId"], str) and 1 <= len(value["sessionId"]) <= 64
        and isinstance(value["nodeId"], str) and 1 <= len(value["nodeId"]) <= 128
    )
    if removal:
        return common
    return (
        common
        and isinstance(value["encryptionKeyHex"], str)
        and len(value["encryptionKeyHex"]) == 130
        and all(ch in "0123456789abcdef" for ch in value["encryptionKeyHex"])
        and isinstance(value["keyId"], str)
        and len(value["keyId"]) == 64
        and all(ch in "0123456789abcdef" for ch in value["keyId"])
        and isinstance(value["expiresAt"], int)
        and not isinstance(value["expiresAt"], bool)
    )


def _valid_node_envelope(value) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"protocol", "type", "id", "payload"}
        and value.get("protocol") == PROTOCOL_VERSIONS["NODE"]
        and value.get("type") in {
            "NODE_HELLO", "NODE_STATE", "ROUTE_REGISTER", "ROUTE_REMOVE",
            "ROUTE_QUERY", "ROUTE_RESULT", "SIGNAL_FORWARD", "ACK",
        }
        and isinstance(value.get("id"), str)
        and 1 <= len(value["id"]) <= 64
        and isinstance(value.get("payload"), dict)
    )
