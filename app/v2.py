# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Secure v2 HTTP admission, TURN lifecycle, and directed WS signaling."""

from __future__ import annotations

import asyncio
import hmac
import hmac
import json
import time

from fastapi import APIRouter, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from cryptography.hazmat.primitives.asymmetric import ec

from .config import Config
from .canonical import canonical_json_bytes
from .hub import Hub
from .health import readiness_reasons
from .metrics import Metrics
from .node_mesh import NodeMesh
from .protocol import PROTOCOL_VERSIONS, ProtocolError, make_error, validate_v2_message
from .rate_limits import TokenBucket
from .session_crypto import generate_challenge, verify_signature
from .strict_json import StrictJsonError, loads_strict
from .trust import NodeTrust
from .turn import TurnCredentialIssuer
from .ws_io import receive_text_frame, send_json_frame


class AdmissionLimiter:
    def __init__(
        self,
        per_client_burst: float = 128.0,
        per_client_refill: float = 2.0,
        global_burst: float = 256.0,
        global_refill: float = 32.0,
    ) -> None:
        self._buckets: dict[str, tuple[TokenBucket, float]] = {}
        self._per_client_burst = per_client_burst
        self._per_client_refill = per_client_refill
        self._global_bucket = TokenBucket(global_burst, global_refill)

    def allow(self, client_key: str) -> bool:
        now = time.monotonic()
        existing = self._buckets.pop(client_key, None)
        bucket = existing[0] if existing is not None else TokenBucket(
            self._per_client_burst, self._per_client_refill,
        )
        self._buckets[client_key] = (bucket, now)
        while len(self._buckets) > 4096:
            self._buckets.pop(next(iter(self._buckets)))
        if not bucket.try_consume():
            return False
        return self._global_bucket.try_consume()


def create_v2_router(
    hub: Hub,
    config: Config,
    trust: NodeTrust,
    metrics: Metrics,
    node_mesh: NodeMesh,
) -> APIRouter:
    router = APIRouter()
    admission_limiter = AdmissionLimiter(
        per_client_burst=config.admission_rate_burst,
        per_client_refill=config.admission_rate_per_second,
        global_burst=config.admission_global_burst,
        global_refill=config.admission_global_per_second,
    )
    admission_crypto_slots = asyncio.Semaphore(max(1, config.admission_crypto_concurrency))
    turn_limiter = AdmissionLimiter(
        per_client_burst=config.turn_rate_burst,
        per_client_refill=config.turn_rate_per_second,
        global_burst=config.turn_global_burst,
        global_refill=config.turn_global_per_second,
    )
    signal_global_limiter = TokenBucket(
        config.signal_global_burst, config.signal_global_per_second,
    )
    turn_issuer = TurnCredentialIssuer(config)

    @router.get("/status")
    async def status():
        protocols = trust.manifest()["payload"]["protocols"]
        return {
            "service": "particle-masterserver",
            "version": 2,
            "nodeId": config.node_id,
            "ready": not readiness_reasons(hub, config, metrics, trust, node_mesh),
            "protocols": protocols,
            "uptimeSeconds": max(0, int(time.time()) - trust.started_at),
        }

    @router.get("/v2/manifest")
    async def manifest():
        return trust.manifest()

    @router.post("/v2/admission")
    async def admission(request: Request):
        client_key = request.client.host if request.client else "unknown"
        if not admission_limiter.allow(client_key):
            metrics.increment("admission_rate_rejections")
            raise HTTPException(
                status_code=429, detail="admission rate limit exceeded", headers={"Retry-After": "1"},
            )
        body = await _bounded_json_request(request, config.max_frame_bytes)
        if set(body) != {"publicKeyHex", "nonce", "protocol"}:
            raise HTTPException(status_code=400, detail="admission request fields are invalid")
        public_key_hex = body.get("publicKeyHex")
        nonce = body.get("nonce")
        protocol = body.get("protocol")
        if not _is_hex_bytes(public_key_hex, 65) or not isinstance(nonce, str) or not 16 <= len(nonce.encode("utf-8")) <= 128:
            metrics.increment("admission_rejections")
            raise HTTPException(status_code=400, detail="invalid publicKeyHex or nonce")
        if protocol != PROTOCOL_VERSIONS["SESSION_V2"]:
            raise HTTPException(status_code=400, detail="unsupported admission protocol")
        try:
            await asyncio.wait_for(admission_crypto_slots.acquire(), timeout=config.admission_crypto_wait_seconds)
        except asyncio.TimeoutError as exc:
            metrics.increment("admission_load_rejections")
            raise HTTPException(
                status_code=503, detail="admission capacity temporarily unavailable", headers={"Retry-After": "1"},
            ) from exc
        try:
            if not _is_p256_point(public_key_hex):
                metrics.increment("admission_rejections")
                raise HTTPException(status_code=400, detail="invalid publicKeyHex or nonce")
            current_manifest = trust.manifest()
            grant = trust.issue_admission(public_key_hex, nonce)
            metrics.increment("admissions_issued")
        finally:
            admission_crypto_slots.release()
        return {
            "grant": grant,
            "expiresAt": grant["payload"]["expiresAt"],
            "nodeId": config.node_id,
            "manifestHash": trust.manifest_hash(current_manifest),
        }

    @router.post("/v2/turn")
    async def turn(request: Request):
        client_key = request.client.host if request.client else "unknown"
        if not turn_limiter.allow(client_key):
            metrics.increment("turn_rate_rejections")
            raise HTTPException(
                status_code=429, detail="TURN rate limit exceeded", headers={"Retry-After": "1"},
            )
        body = await _bounded_json_request(request, config.max_frame_bytes)
        if set(body) != {"grant", "publicKeyHex"}:
            raise HTTPException(status_code=400, detail="TURN request fields are invalid")
        grant = body.get("grant")
        public_key_hex = body.get("publicKeyHex")
        if not isinstance(grant, dict) or not isinstance(public_key_hex, str) or not trust.verify_admission(grant, public_key_hex):
            raise HTTPException(status_code=401, detail="valid admission grant required")
        try:
            credentials = turn_issuer.issue(public_key_hex)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=503, detail="TURN is unavailable") from exc
        metrics.increment("turn_credentials_issued")
        return credentials

    @router.get("/metrics")
    async def prometheus_metrics(request: Request):
        client_host = request.client.host if request.client else ""
        authorization = request.headers.get("authorization", "")
        forwarded = any(request.headers.get(name) for name in (
            "forwarded", "x-forwarded-for", "x-real-ip", "cf-connecting-ip",
        ))
        loopback = client_host in {"127.0.0.1", "::1", "localhost"} and not forwarded
        token_ok = bool(config.metrics_token) and hmac.compare_digest(
            authorization, f"Bearer {config.metrics_token}",
        )
        if not loopback and not token_ok:
            return Response(status_code=403)
        metrics.gauge("active_sessions", hub.session_count())
        metrics.gauge("active_routes", len(hub.routes))
        return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")

    @router.websocket("/v2/ws")
    async def v2_websocket(websocket: WebSocket):
        if not _origin_allowed(websocket, config):
            metrics.increment("origin_rejections")
            await websocket.close(code=1008, reason="origin not allowed")
            return
        # Particle protocol namespaces contain '/', which isn't legal in an
        # RFC 6455 Sec-WebSocket-Protocol token. The namespace is therefore
        # negotiated and enforced in every signed/validated envelope.
        await websocket.accept()
        if hub.session_count() >= config.max_concurrency:
            await websocket.close(code=1013, reason="capacity")
            return
        session_id = hub.create_session(websocket)
        proof_deadline = time.monotonic() + config.proof_deadline_seconds
        try:
            while True:
                sess = hub.sessions.get(session_id)
                if sess is None:
                    break
                if sess["proven"]:
                    raw = await receive_text_frame(websocket)
                else:
                    remaining = proof_deadline - time.monotonic()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    raw = await asyncio.wait_for(receive_text_frame(websocket), timeout=remaining)
                if len(raw.encode("utf-8")) > config.max_frame_bytes:
                    await _v2_error(websocket, "frame-too-large", "message exceeds max frame size")
                    continue
                if not hub.rate_limiter.check(session_id, "MESSAGE"):
                    metrics.increment("rate_rejections")
                    await _v2_error(websocket, "rate-limited", "inbound message rate exceeded")
                    await websocket.close(code=1008, reason="message rate exceeded")
                    break
                if not hub.global_message_limiter.try_consume():
                    metrics.increment("message_global_rate_rejections")
                    await _v2_error(websocket, "capacity", "global message capacity exceeded")
                    await websocket.close(code=1013, reason="global message capacity")
                    break
                try:
                    message = loads_strict(
                        raw, max_bytes=config.max_frame_bytes, max_depth=config.max_json_depth,
                        max_nodes=config.max_json_nodes, max_string_bytes=config.max_frame_bytes,
                    )
                    validate_v2_message(message)
                except StrictJsonError:
                    await _v2_error(websocket, "bad-json", "message is not valid JSON")
                    continue
                except ProtocolError as exc:
                    await _v2_error(websocket, exc.code, exc.message, message.get("id") if isinstance(message, dict) else None)
                    continue
                await _handle_v2_message(
                    hub, config, trust, metrics, node_mesh, signal_global_limiter,
                    session_id, websocket, message,
                )
        except asyncio.TimeoutError:
            metrics.increment("proof_timeouts")
            await _v2_error(websocket, "proof-timeout", "did not complete PROVE within the deadline")
            try:
                await websocket.close(code=1008, reason="proof timeout")
            except Exception:
                pass
        except WebSocketDisconnect:
            pass
        finally:
            sess = hub.sessions.get(session_id)
            if sess is not None:
                for route_tag in list(sess["routes"]):
                    await node_mesh.remove_local_route(route_tag, session_id)
            hub.remove_session(session_id)

    @router.websocket("/v2/node")
    async def node_websocket(websocket: WebSocket):
        if not config.node_mesh_enabled:
            await websocket.close(code=1008, reason="node mesh disabled")
            return
        if config.node_mesh_require_mtls:
            verified = websocket.headers.get(config.node_mesh_client_verify_header.lower(), "")
            proxy_token = websocket.headers.get(config.node_mesh_proxy_token_header.lower(), "")
            if (
                verified != config.node_mesh_client_verify_value
                or not config.node_mesh_proxy_token
                or not hmac.compare_digest(
                    proxy_token.encode("utf-8"), config.node_mesh_proxy_token.encode("utf-8"),
                )
            ):
                metrics.increment("node_mesh_mtls_rejections")
                await websocket.close(code=1008, reason="trusted mTLS proxy required")
                return
        await node_mesh.accept(websocket)

    return router


async def _handle_v2_message(
    hub: Hub,
    config: Config,
    trust: NodeTrust,
    metrics: Metrics,
    node_mesh: NodeMesh,
    signal_global_limiter: TokenBucket,
    session_id: str,
    websocket: WebSocket,
    message: dict,
) -> None:
    sess = hub.sessions[session_id]
    msg_type = message["type"]
    payload = message.get("payload") or {}
    if not sess["proven"] and msg_type not in {"HELLO", "PROVE", "PING"}:
        await _v2_error(websocket, "not-proven", "complete HELLO/PROVE before other operations", message.get("id"))
        return
    if msg_type == "HELLO":
        if sess.get("challenge") is not None or sess["proven"]:
            await _v2_error(websocket, "invalid-state", "HELLO is only valid once per session", message.get("id"))
            return
        identity_key_hex = payload["identityKeyHex"]
        if not _is_p256_point(identity_key_hex) or not _is_p256_point(payload["encryptionKeyHex"]):
            await _v2_error(websocket, "bad-key", "identity and encryption keys must be valid P-256 points", message.get("id"))
            return
        if not trust.verify_admission(payload["grant"], identity_key_hex):
            metrics.increment("admission_rejections")
            await _v2_error(websocket, "bad-grant", "admission grant is invalid or expired", message.get("id"))
            return
        challenge = generate_challenge()
        sess["challenge"] = challenge
        sess["public_key_raw"] = bytes.fromhex(identity_key_hex)
        sess["proven"] = False
        hub.set_v2_identity(session_id, identity_key_hex, payload["encryptionKeyHex"])
        manifest = trust.manifest()
        await send_json_frame(websocket, {
            "protocol": PROTOCOL_VERSIONS["SESSION_V2"],
            "type": "CHALLENGE",
            "inReplyTo": message.get("id"),
            "payload": {
                "sessionId": session_id,
                "challengeHex": challenge.hex(),
                "nodeId": config.node_id,
                "manifestHash": trust.manifest_hash(manifest),
            },
        })
    elif msg_type == "PROVE":
        if sess["proven"] or sess.get("challenge") is None:
            await _v2_error(websocket, "invalid-state", "PROVE must follow this session's HELLO", message.get("id"))
            return
        if not hub.rate_limiter.check(session_id, "PROVE"):
            metrics.increment("proof_rate_rejections")
            await _v2_error(websocket, "rate-limited", "proof attempt limit exceeded", message.get("id"))
            await websocket.close(code=1008, reason="proof attempt limit exceeded")
            return
        signature = bytes.fromhex(payload["signatureHex"])
        if not sess.get("challenge") or not verify_signature(sess.get("public_key_raw"), sess["challenge"], signature):
            metrics.increment("proof_failures")
            await _v2_error(websocket, "prove-failed", "signature did not verify", message.get("id"))
            return
        sess["proven"] = True
        sess["challenge"] = None
        hub.touch_heartbeat(session_id)
        metrics.increment("proof_successes")
        await send_json_frame(websocket, {
            "protocol": PROTOCOL_VERSIONS["SESSION_V2"],
            "type": "SESSION_READY",
            "inReplyTo": message.get("id"),
            "payload": {"sessionId": session_id, "routeLeaseSeconds": config.route_lease_seconds},
        })
    elif msg_type == "PING":
        if not hub.rate_limiter.check(session_id, "HEARTBEAT"):
            metrics.increment("rate_rejections")
            await _v2_error(websocket, "rate-limited", "PING rate limit exceeded", message.get("id"))
        else:
            hub.touch_heartbeat(session_id)
            await send_json_frame(websocket, {"protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "PONG", "inReplyTo": message.get("id")})
    elif msg_type == "ATTACH_ROUTE":
        if not hub.rate_limiter.check(session_id, "ATTACH_ROUTE"):
            metrics.increment("rate_rejections")
            await _v2_error(websocket, "rate-limited", "ATTACH_ROUTE rate limit exceeded", message.get("id"))
            return
        route_tag = payload["routeTag"]
        try:
            hub.attach_route(session_id, route_tag)
        except ValueError:
            await _v2_error(websocket, "too-many-routes", f"session route limit is {config.max_routes_per_session}", message.get("id"))
            return
        await node_mesh.register_local_route(route_tag, session_id)
        await send_json_frame(websocket, {
            "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "inReplyTo": message.get("id"),
            "payload": {"routeTag": route_tag, "ok": True, "leaseSeconds": config.route_lease_seconds},
        })
    elif msg_type == "DETACH_ROUTE":
        route_tag = payload["routeTag"]
        hub.detach_route(session_id, route_tag)
        await node_mesh.remove_local_route(route_tag, session_id)
        await send_json_frame(websocket, {
            "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "DETACH_ROUTE", "inReplyTo": message.get("id"),
            "payload": {"routeTag": route_tag, "ok": True},
        })
    elif msg_type == "DISCOVER":
        if not hub.rate_limiter.check(session_id, "DISCOVER"):
            metrics.increment("rate_rejections")
            await _v2_error(websocket, "rate-limited", "DISCOVER rate limit exceeded", message.get("id"))
            return
        route_tag = payload["routeTag"]
        if route_tag not in sess["routes"]:
            metrics.increment("route_authorization_rejections")
            await _v2_error(
                websocket, "not-attached", "attach to the route before discovery", message.get("id"),
            )
            return
        local = hub.route_peer_descriptors(route_tag, exclude=session_id)
        remote = await node_mesh.discover(route_tag)
        peers = {item["sessionId"]: item for item in [*local, *remote] if item.get("sessionId") != session_id}
        await send_json_frame(websocket, {
            "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "PEERS", "inReplyTo": message.get("id"),
            "payload": {"routeTag": route_tag, "peers": list(peers.values())[: config.max_fanout]},
        })
    elif msg_type == "SIGNAL":
        await _handle_v2_signal(
            hub, config, metrics, node_mesh, signal_global_limiter,
            session_id, websocket, message,
        )
    else:
        await _v2_error(websocket, "unsupported-type", f"{msg_type} is not valid in this session state", message.get("id"))


async def _handle_v2_signal(
    hub: Hub,
    config: Config,
    metrics: Metrics,
    node_mesh: NodeMesh,
    signal_global_limiter: TokenBucket,
    session_id: str,
    websocket: WebSocket,
    message: dict,
) -> None:
    payload = message["payload"]
    route_tag = payload["routeTag"]
    now = int(time.time())
    if route_tag not in hub.sessions[session_id]["routes"]:
        await _v2_error(websocket, "not-attached", "sender is not attached to route", message.get("id"))
        return
    sender = hub.sessions[session_id]
    if (
        payload["fromSessionId"] != session_id
        or payload["senderKeyId"] != sender.get("identity_key_id")
        or payload["senderIdentityKeyHex"] != sender.get("identity_key_hex")
    ):
        await _v2_error(websocket, "sender-mismatch", "signal sender binding does not match the proven session", message.get("id"))
        return
    if not now - 5 <= payload["expiresAt"] <= now + 300:
        await _v2_error(websocket, "expired-signal", "signal expiry is outside the accepted window", message.get("id"))
        return
    if not hub.rate_limiter.check(session_id, "SIGNAL_V2"):
        metrics.increment("rate_rejections")
        await _v2_error(websocket, "rate-limited", "SIGNAL rate limit exceeded", message.get("id"))
        return
    if not signal_global_limiter.try_consume():
        metrics.increment("signal_global_rate_rejections")
        await _v2_error(websocket, "capacity", "global signal verification capacity exceeded", message.get("id"))
        return
    signed_fields = {key: value for key, value in payload.items() if key != "signatureHex"}
    if not verify_signature(
        sender.get("public_key_raw"), canonical_json_bytes(signed_fields), bytes.fromhex(payload["signatureHex"]),
    ):
        metrics.increment("signal_signature_rejections")
        await _v2_error(websocket, "bad-signal-signature", "signal sender signature did not verify", message.get("id"))
        return
    replay_key = f"v2:{session_id}:{payload['messageId']}:{payload['sequence']}"
    if (
        payload["sequence"] <= hub.sessions[session_id]["last_signal_sequence"]
        or not hub.check_and_mark_seen(replay_key, config.dedupe_window_seconds)
    ):
        metrics.increment("replay_rejections")
        await _v2_error(websocket, "replay", "message id and sequence were already accepted", message.get("id"))
        return
    hub.sessions[session_id]["last_signal_sequence"] = payload["sequence"]
    target_session_id = payload["toSessionId"]
    target_descriptor = hub.peer_descriptor(target_session_id) or node_mesh.remote_descriptor(target_session_id)
    if target_descriptor is None or target_descriptor.get("keyId") != payload["keyId"]:
        await _v2_error(websocket, "unknown-recipient", "recipient is unavailable or key id does not match", message.get("id"))
        return
    outgoing = {
        "protocol": PROTOCOL_VERSIONS["SIGNAL_V2"],
        "type": "SIGNAL",
        "id": message.get("id"),
        "payload": dict(payload),
    }
    started = time.perf_counter()
    if target_session_id in hub.route_subscribers(route_tag, exclude=session_id):
        delivered = await hub.send_session(target_session_id, outgoing)
    else:
        delivered = await node_mesh.forward_signal(route_tag, target_session_id, outgoing)
    metrics.observe("signal_relay_seconds", time.perf_counter() - started)
    metrics.increment("v2_signal_deliveries", 1 if delivered else 0)
    await send_json_frame(websocket, {
        "protocol": PROTOCOL_VERSIONS["SIGNAL_V2"],
        "type": "SIGNAL_ACK",
        "inReplyTo": message.get("id"),
        "payload": {"messageId": payload["messageId"], "accepted": True, "delivered": bool(delivered)},
    })


async def _v2_error(websocket: WebSocket, code: str, message: str, in_reply_to: str | None = None) -> None:
    error = make_error(code, message, in_reply_to)
    error["protocol"] = PROTOCOL_VERSIONS["SESSION_V2"]
    try:
        await send_json_frame(websocket, error)
    except WebSocketDisconnect:
        raise
    except Exception:
        pass


async def _bounded_json_request(request: Request, maximum: int) -> dict:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum:
            raise HTTPException(status_code=413, detail="request body too large")
        body.extend(chunk)
    try:
        value = loads_strict(bytes(body), max_bytes=maximum, max_depth=16, max_nodes=512, max_string_bytes=maximum)
    except StrictJsonError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    return value


def _is_hex_bytes(value, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length * 2:
        return False
    try:
        return len(bytes.fromhex(value)) == length
    except ValueError:
        return False


def _is_p256_point(value) -> bool:
    if not _is_hex_bytes(value, 65):
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(value))
        return True
    except ValueError:
        return False


def _origin_allowed(websocket: WebSocket, config: Config) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return True
    try:
        allowed = json.loads(config.allowed_origins_json)
    except json.JSONDecodeError:
        return False
    return origin in allowed
