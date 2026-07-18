# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/routes.py — the single WebSocket endpoint (network plan
§7: keep the public API tiny — GET /healthz, GET /readyz, WS /v1/ws, nothing
else). Reactive, not polling (network plan §8): connect once, prove once,
attach routes, then only exchange changes/signals.

Message flow implemented in this build:
  HELLO -> {challenge}            (any time, resets proof)
  PROVE -> {ok}                    (must follow HELLO; unlocks other ops)
  PING  -> PONG                    (heartbeat; allowed pre-proof so a client
                                     can keep a socket open while proving)
  ATTACH_ROUTE / DETACH_ROUTE      (requires proof)
  DISCOVER -> PEERS                (requires proof; live subscribers of a route)
  SIGNAL / FORWARD / PUBLISH       (requires proof; relayed to route
                                     subscribers with TTL decrement + dedupe
                                     + rate limit + fanout cap — payload is
                                     opaque to this server, network plan §12)
"""

from __future__ import annotations

import json
import asyncio
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .canonical import content_hash_hex
from .config import Config
from .hub import Hub
from .protocol import PROTOCOL_VERSIONS, ProtocolError, make_error, validate_v1_message
from .session_crypto import generate_challenge, verify_signature
from .strict_json import StrictJsonError, loads_strict
from .ws_io import receive_text_frame, send_json_frame


def create_ws_router(hub: Hub, config: Config) -> APIRouter:
    router = APIRouter()

    @router.websocket("/v1/ws")
    async def ws_endpoint(websocket: WebSocket):
        if not _origin_allowed(websocket, config):
            hub.metrics.increment("origin_rejections")
            await websocket.close(code=1008, reason="origin not allowed")
            return
        await websocket.accept()

        if hub.session_count() >= config.max_concurrency:
            await websocket.close(code=1013)  # "try again later"
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
                    await _send_error(websocket, "frame-too-large", "message exceeds max frame size")
                    continue
                if not hub.rate_limiter.check(session_id, "MESSAGE"):
                    hub.metrics.increment("rate_rejections")
                    await _send_error(websocket, "rate-limited", "inbound message rate exceeded")
                    await websocket.close(code=1008, reason="message rate exceeded")
                    break
                if not hub.global_message_limiter.try_consume():
                    hub.metrics.increment("message_global_rate_rejections")
                    await _send_error(websocket, "capacity", "global message capacity exceeded")
                    await websocket.close(code=1013, reason="global message capacity")
                    break

                try:
                    data = loads_strict(
                        raw, max_bytes=config.max_frame_bytes, max_depth=config.max_json_depth,
                        max_nodes=config.max_json_nodes, max_string_bytes=config.max_frame_bytes,
                    )
                    validate_v1_message(data)
                except StrictJsonError:
                    await _send_error(websocket, "bad-json", "message is not valid JSON")
                    continue
                except ProtocolError as exc:
                    await _send_error(websocket, exc.code, exc.message)
                    continue

                sess = hub.sessions.get(session_id)
                if sess is None:
                    break

                msg_type = data["type"]

                if not sess["proven"] and msg_type not in ("HELLO", "PROVE", "PING"):
                    await _send_error(websocket, "not-proven", "complete HELLO/PROVE before other operations")
                elif msg_type == "HELLO":
                    if sess.get("challenge") is not None or sess["proven"]:
                        await _send_error(websocket, "invalid-state", "HELLO is only valid once per session")
                    else:
                        await _handle_hello(session_id, sess, websocket, data)
                elif msg_type == "PROVE":
                    if sess["proven"] or sess.get("challenge") is None:
                        await _send_error(websocket, "invalid-state", "PROVE must follow this session's HELLO")
                    else:
                        await _handle_prove(hub, session_id, sess, websocket, data)
                elif msg_type == "PING":
                    if not hub.rate_limiter.check(session_id, "HEARTBEAT"):
                        hub.metrics.increment("rate_rejections")
                        await _send_error(websocket, "rate-limited", "PING rate limit exceeded")
                    else:
                        hub.touch_heartbeat(session_id)
                        await send_json_frame(websocket, {"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PONG"})
                elif msg_type == "ATTACH_ROUTE":
                    await _handle_attach_route(hub, config, session_id, websocket, data)
                elif msg_type == "DETACH_ROUTE":
                    await _handle_detach_route(hub, session_id, websocket, data)
                elif msg_type == "DISCOVER":
                    await _handle_discover(hub, session_id, websocket, data)
                elif msg_type in ("SIGNAL", "FORWARD", "PUBLISH"):
                    await _handle_route_message(hub, config, session_id, websocket, data, msg_type)
                else:
                    await _send_error(websocket, "unsupported-type", f"{msg_type} not handled by this build")

        except asyncio.TimeoutError:
            hub.metrics.increment("proof_timeouts")
            await _send_error(websocket, "proof-timeout", "did not complete PROVE within the deadline")
            try:
                await websocket.close(code=1008, reason="proof timeout")
            except Exception:
                pass
        except WebSocketDisconnect:
            pass
        finally:
            hub.remove_session(session_id)

    return router


def _origin_allowed(websocket: WebSocket, config: Config) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return True  # native/CLI clients do not send browser Origin
    try:
        allowed = json.loads(config.allowed_origins_json)
    except json.JSONDecodeError:
        return False
    return origin in allowed


async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
    try:
        await send_json_frame(websocket, make_error(code, message))
    except WebSocketDisconnect:
        raise
    except Exception:
        pass


async def _handle_hello(session_id: str, sess: dict, websocket: WebSocket, data: dict) -> None:
    challenge = generate_challenge()
    sess["challenge"] = challenge
    sess["proven"] = False
    sess["public_key_raw"] = None
    public_key_hex = (data.get("payload") or {}).get("publicKeyHex")
    if public_key_hex:
        try:
            sess["public_key_raw"] = bytes.fromhex(public_key_hex)
        except ValueError:
            sess["public_key_raw"] = None
    await send_json_frame(websocket, {
        "protocol": PROTOCOL_VERSIONS["SESSION"],
        "type": "HELLO",
        "payload": {"sessionId": session_id, "challengeHex": challenge.hex()},
    })


async def _handle_prove(hub: Hub, session_id: str, sess: dict, websocket: WebSocket, data: dict) -> None:
    if not hub.rate_limiter.check(session_id, "PROVE"):
        hub.metrics.increment("proof_rate_rejections")
        await _send_error(websocket, "rate-limited", "proof attempt limit exceeded")
        await websocket.close(code=1008, reason="proof attempt limit exceeded")
        return
    challenge = sess.get("challenge")
    public_key_raw = sess.get("public_key_raw")
    signature_hex = (data.get("payload") or {}).get("signatureHex")
    if not challenge or not public_key_raw or not signature_hex:
        await _send_error(websocket, "prove-missing-fields", "HELLO with a publicKeyHex must precede PROVE")
        return
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        await _send_error(websocket, "bad-signature-encoding", "signatureHex must be hex")
        return
    if not verify_signature(public_key_raw, challenge, signature):
        await _send_error(websocket, "prove-failed", "signature did not verify against the HELLO challenge")
        return
    sess["proven"] = True
    sess["challenge"] = None
    hub.metrics.increment("proof_successes")
    hub.touch_heartbeat(session_id)
    await send_json_frame(websocket, {"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PROVE", "payload": {"ok": True}})


async def _handle_attach_route(hub: Hub, config: Config, session_id: str, websocket: WebSocket, data: dict) -> None:
    if not hub.rate_limiter.check(session_id, "ATTACH_ROUTE"):
        await _send_error(websocket, "rate-limited", "ATTACH_ROUTE rate limit exceeded")
        return
    route_id = (data.get("payload") or {}).get("routeId")
    if not route_id:
        await _send_error(websocket, "missing-routeId", "ATTACH_ROUTE requires payload.routeId")
        return
    try:
        hub.attach_route(session_id, route_id, max_routes=config.max_v1_routes_per_session)
    except ValueError:
        await _send_error(websocket, "too-many-routes", f"session already attached to {config.max_v1_routes_per_session} routes")
        return
    await send_json_frame(websocket, {
        "protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": route_id, "ok": True},
    })


async def _handle_detach_route(hub: Hub, session_id: str, websocket: WebSocket, data: dict) -> None:
    route_id = (data.get("payload") or {}).get("routeId")
    if route_id:
        hub.detach_route(session_id, route_id)
    await send_json_frame(websocket, {
        "protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "DETACH_ROUTE", "payload": {"routeId": route_id, "ok": True},
    })


async def _handle_discover(hub: Hub, session_id: str, websocket: WebSocket, data: dict) -> None:
    if not hub.rate_limiter.check(session_id, "DISCOVER"):
        hub.metrics.increment("rate_rejections")
        await _send_error(websocket, "rate-limited", "DISCOVER rate limit exceeded")
        return
    route_id = (data.get("payload") or {}).get("routeId")
    if route_id not in hub.sessions[session_id]["routes"]:
        hub.metrics.increment("route_authorization_rejections")
        await _send_error(websocket, "not-attached", "attach to the route before discovery")
        return
    peers = hub.route_subscribers(route_id, exclude=session_id) if route_id else []
    await send_json_frame(websocket, {
        "protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "PEERS", "payload": {"routeId": route_id, "peers": peers[:16]},
    })


async def _handle_route_message(hub: Hub, config: Config, session_id: str, websocket: WebSocket, data: dict, msg_type: str) -> None:
    op = "FORWARD" if msg_type == "FORWARD" else "SIGNAL"
    if not hub.rate_limiter.check(session_id, op):
        await _send_error(websocket, "rate-limited", f"{msg_type} rate limit exceeded")
        return

    payload = data.get("payload") or {}
    route_id = payload.get("routeId")
    if not route_id:
        await _send_error(websocket, "missing-routeId", f"{msg_type} requires payload.routeId")
        return
    if route_id not in hub.sessions[session_id]["routes"]:
        hub.metrics.increment("route_authorization_rejections")
        await _send_error(websocket, "not-attached", "attach to the route before signaling")
        return

    dedupe_key = content_hash_hex({"routeId": route_id, "type": msg_type, "payload": payload})
    if not hub.check_and_mark_seen(dedupe_key, config.dedupe_window_seconds):
        return  # silent drop — exact duplicate already forwarded recently

    ttl = payload.get("ttl", config.max_hops)
    if isinstance(ttl, int) and ttl <= 0:
        return  # hop-exhausted, drop

    subscribers = hub.route_subscribers(route_id, exclude=session_id)[: config.max_fanout]
    outgoing = {**data, "payload": {**payload, "ttl": (ttl - 1) if isinstance(ttl, int) else ttl}}
    delivered = await asyncio.gather(*(hub.send_session(sid, outgoing) for sid in subscribers))
    hub.metrics.increment("v1_signal_deliveries", sum(bool(value) for value in delivered))
