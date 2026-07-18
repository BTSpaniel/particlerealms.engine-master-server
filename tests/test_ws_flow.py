# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
End-to-end WebSocket flow tests using FastAPI's synchronous TestClient
(no real network socket, no external process). Signatures are generated
with `cryptography` in the same raw IEEE P1363 (r||s) format WebCrypto's
`{name:'ECDSA', hash:'SHA-256'}` produces in the real JS client, so this
also exercises app/session_crypto.py's format-conversion path.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app
from app.protocol import PROTOCOL_VERSIONS


def _make_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    raw_point = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    return private_key, raw_point


def _sign_raw(private_key, message: bytes) -> bytes:
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = ec_utils.decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _hello_and_prove(ws) -> None:
    private_key, raw_point = _make_keypair()
    ws.send_json({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "HELLO", "payload": {"publicKeyHex": raw_point.hex()}})
    hello_resp = ws.receive_json()
    assert hello_resp["type"] == "HELLO"
    challenge = bytes.fromhex(hello_resp["payload"]["challengeHex"])
    signature = _sign_raw(private_key, challenge)
    ws.send_json({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PROVE", "payload": {"signatureHex": signature.hex()}})
    prove_resp = ws.receive_json()
    assert prove_resp["type"] == "PROVE" and prove_resp["payload"]["ok"] is True


def _client() -> TestClient:
    return TestClient(create_app(Config()))


def test_hello_prove_flow_succeeds_with_a_genuine_signature():
    with _client().websocket_connect("/v1/ws") as ws:
        _hello_and_prove(ws)


def test_proven_v1_session_cannot_restart_the_proof_state_machine():
    with _client().websocket_connect("/v1/ws") as ws:
        _hello_and_prove(ws)
        _, raw_point = _make_keypair()
        ws.send_json({
            "protocol": PROTOCOL_VERSIONS["SESSION"], "type": "HELLO",
            "payload": {"publicKeyHex": raw_point.hex()},
        })
        response = ws.receive_json()
        assert response["type"] == "ERROR" and response["code"] == "invalid-state"


def test_prove_fails_with_a_bad_signature():
    with _client().websocket_connect("/v1/ws") as ws:
        _, raw_point = _make_keypair()
        ws.send_json({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "HELLO", "payload": {"publicKeyHex": raw_point.hex()}})
        ws.receive_json()
        ws.send_json({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PROVE", "payload": {"signatureHex": bytes(64).hex()}})
        resp = ws.receive_json()
        assert resp["type"] == "ERROR" and resp["code"] == "prove-failed"


def test_v1_closes_after_three_failed_proof_verifications():
    with _client().websocket_connect("/v1/ws") as ws:
        _, raw_point = _make_keypair()
        ws.send_json({
            "protocol": PROTOCOL_VERSIONS["SESSION"], "type": "HELLO",
            "payload": {"publicKeyHex": raw_point.hex()},
        })
        ws.receive_json()
        bad_prove = {
            "protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PROVE",
            "payload": {"signatureHex": bytes(64).hex()},
        }
        for _ in range(3):
            ws.send_json(bad_prove)
            assert ws.receive_json()["code"] == "prove-failed"
        ws.send_json(bad_prove)
        assert ws.receive_json()["code"] == "rate-limited"


def test_unproven_session_cannot_attach_a_route():
    with _client().websocket_connect("/v1/ws") as ws:
        ws.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "r1"}})
        resp = ws.receive_json()
        assert resp["type"] == "ERROR" and resp["code"] == "not-proven"


def test_reconnect_as_a_fresh_session_still_requires_its_own_proof():
    client = _client()
    with client.websocket_connect("/v1/ws") as ws1:
        _hello_and_prove(ws1)
    # A brand-new connection is a brand-new session_id — proof does not carry over.
    with client.websocket_connect("/v1/ws") as ws2:
        ws2.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "r1"}})
        resp = ws2.receive_json()
        assert resp["type"] == "ERROR" and resp["code"] == "not-proven"


def test_silent_v1_client_hits_independent_proof_deadline():
    client = TestClient(create_app(Config(proof_deadline_seconds=0.02)))
    with client.websocket_connect("/v1/ws") as ws:
        response = ws.receive_json()
        assert response["type"] == "ERROR" and response["code"] == "proof-timeout"


def test_signal_relays_to_route_subscribers_with_ttl_decrement():
    client = _client()
    with client.websocket_connect("/v1/ws") as ws_a, client.websocket_connect("/v1/ws") as ws_b:
        _hello_and_prove(ws_a)
        _hello_and_prove(ws_b)

        ws_a.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "shared-route"}})
        assert ws_a.receive_json()["payload"]["ok"] is True
        ws_b.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "shared-route"}})
        assert ws_b.receive_json()["payload"]["ok"] is True

        signal_msg = {
            "protocol": PROTOCOL_VERSIONS["SIGNAL"], "type": "SIGNAL",
            "payload": {"routeId": "shared-route", "ttl": 4, "offer": "hello-b"},
        }
        ws_a.send_json(signal_msg)
        received = ws_b.receive_json()
        assert received["type"] == "SIGNAL"
        assert received["payload"]["offer"] == "hello-b"
        assert received["payload"]["ttl"] == 3  # decremented by exactly one hop

        # An exact duplicate must be dropped silently — prove it by checking ws_b's
        # NEXT message is the ack for a follow-up op, not a second SIGNAL queued ahead of it.
        ws_a.send_json(signal_msg)
        ws_b.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "DETACH_ROUTE", "payload": {"routeId": "shared-route"}})
        next_on_b = ws_b.receive_json()
        assert next_on_b["type"] == "DETACH_ROUTE", "a duplicate SIGNAL must not have been forwarded"


def test_signal_with_ttl_exhausted_is_not_forwarded():
    client = _client()
    with client.websocket_connect("/v1/ws") as ws_a, client.websocket_connect("/v1/ws") as ws_b:
        _hello_and_prove(ws_a)
        _hello_and_prove(ws_b)
        for ws in (ws_a, ws_b):
            ws.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "r1"}})
            ws.receive_json()

        ws_a.send_json({
            "protocol": PROTOCOL_VERSIONS["SIGNAL"], "type": "SIGNAL",
            "payload": {"routeId": "r1", "ttl": 0, "offer": "should-not-arrive"},
        })
        ws_b.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "DETACH_ROUTE", "payload": {"routeId": "r1"}})
        next_on_b = ws_b.receive_json()
        assert next_on_b["type"] == "DETACH_ROUTE", "a ttl-exhausted SIGNAL must not have been forwarded"


def test_discover_lists_other_route_subscribers_excluding_self():
    client = _client()
    with client.websocket_connect("/v1/ws") as ws_a, client.websocket_connect("/v1/ws") as ws_b:
        _hello_and_prove(ws_a)
        _hello_and_prove(ws_b)
        for ws in (ws_a, ws_b):
            ws.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "ATTACH_ROUTE", "payload": {"routeId": "r1"}})
            ws.receive_json()

        ws_a.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "DISCOVER", "payload": {"routeId": "r1"}})
        resp = ws_a.receive_json()
        assert resp["type"] == "PEERS"
        assert len(resp["payload"]["peers"]) == 1


def test_v1_discovery_and_signaling_require_route_membership():
    with _client().websocket_connect("/v1/ws") as ws:
        _hello_and_prove(ws)
        ws.send_json({
            "protocol": PROTOCOL_VERSIONS["ROUTE"], "type": "DISCOVER",
            "payload": {"routeId": "not-attached"},
        })
        response = ws.receive_json()
        assert response["type"] == "ERROR" and response["code"] == "not-attached"
        ws.send_json({
            "protocol": PROTOCOL_VERSIONS["SIGNAL"], "type": "SIGNAL",
            "payload": {"routeId": "not-attached", "ttl": 4, "offer": "blocked"},
        })
        response = ws.receive_json()
        assert response["type"] == "ERROR" and response["code"] == "not-attached"


def test_oversized_frame_is_rejected():
    with _client().websocket_connect("/v1/ws") as ws:
        huge = {"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PING", "payload": {"junk": "x" * 200_000}}
        ws.send_json(huge)
        resp = ws.receive_json()
        assert resp["type"] == "ERROR" and resp["code"] == "frame-too-large"
