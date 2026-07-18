# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import hashlib
import base64
import hmac
import time

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import Config
from app.canonical import canonical_json_bytes
from app.main import create_app
from app.protocol import PROTOCOL_VERSIONS
from app.v2 import AdmissionLimiter


def _identity():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    return private_key, public_raw


def _sign(private_key, message: bytes) -> str:
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = ec_utils.decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def _admit(client: TestClient, public_raw: bytes):
    response = client.post("/v2/admission", json={
        "publicKeyHex": public_raw.hex(),
        "nonce": "0123456789abcdef",
        "protocol": PROTOCOL_VERSIONS["SESSION_V2"],
    })
    assert response.status_code == 200
    return response.json()["grant"]


def _prove(client: TestClient, ws, private_key, public_raw):
    grant = _admit(client, public_raw)
    ws.send_json({
        "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "HELLO", "id": "hello",
        "payload": {"grant": grant, "identityKeyHex": public_raw.hex(), "encryptionKeyHex": public_raw.hex()},
    })
    challenge = ws.receive_json()
    assert challenge["type"] == "CHALLENGE"
    signature = _sign(private_key, bytes.fromhex(challenge["payload"]["challengeHex"]))
    ws.send_json({
        "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "PROVE", "id": "prove",
        "payload": {"signatureHex": signature},
    })
    ready = ws.receive_json()
    assert ready["type"] == "SESSION_READY"
    return ready["payload"]["sessionId"]


def _app(**overrides):
    return create_app(Config(**overrides))


def _signal_payload(private_key, public_raw, session_id, target_session_id, target_public, route_tag, message_id):
    payload = {
        "routeTag": route_tag,
        "fromSessionId": session_id,
        "toSessionId": target_session_id,
        "messageId": message_id,
        "sequence": 1,
        "expiresAt": int(time.time()) + 30,
        "keyId": hashlib.sha256(target_public).hexdigest(),
        "senderKeyId": hashlib.sha256(public_raw).hexdigest(),
        "senderIdentityKeyHex": public_raw.hex(),
        "encHex": public_raw.hex(),
        "ciphertextHex": "00" * 32,
    }
    payload["signatureHex"] = _sign(private_key, canonical_json_bytes(payload))
    return payload


def test_node_endpoint_requires_proxy_attestation_in_addition_to_mtls_status():
    proxy_secret = "p" * 32
    app = _app(node_mesh_enabled=True, node_mesh_proxy_token=proxy_secret)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(
                "/v2/node", headers={"x-ssl-client-verify": "SUCCESS"},
            ):
                pass
        assert rejected.value.code == 1008

        with client.websocket_connect("/v2/node", headers={
            "x-ssl-client-verify": "SUCCESS",
            "x-particle-node-proxy-token": proxy_secret,
        }) as websocket:
            websocket.send_text("{}")
            closed = websocket.receive()
            assert closed["type"] == "websocket.close" and closed["code"] == 1008


def test_status_manifest_admission_and_protected_turn_lifecycle():
    turn_json = '[{"urls":"turns:turn.example:5349","username":"u","credential":"c"}]'
    app = _app(turn_servers_json=turn_json, metrics_token="metrics-secret")
    with TestClient(app) as client:
        status = client.get("/status").json()
        assert status["ready"] is True and "particle-session/2" in status["protocols"]
        manifest = client.get("/v2/manifest").json()
        assert manifest["payload"]["signingKeyId"] == app.state.trust.key_id
        _, public_raw = _identity()
        grant = _admit(client, public_raw)
        denied = client.post("/v2/turn", json={"grant": {}, "publicKeyHex": public_raw.hex()})
        assert denied.status_code == 401
        turn = client.post("/v2/turn", json={"grant": grant, "publicKeyHex": public_raw.hex()})
        assert turn.status_code == 200 and turn.json()["expiresAt"] > int(time.time())
        metrics = client.get("/metrics", headers={"authorization": "Bearer metrics-secret"})
        assert metrics.status_code == 200 and "particle_admissions_issued_total" in metrics.text


def test_turn_rest_credentials_are_short_lived_and_identity_bound():
    app = _app(
        turn_urls_json='["turn:turn.example:3478?transport=udp","turns:turn.example:5349"]',
        turn_shared_secret="turn-rest-secret",
        turn_ttl_seconds=300,
    )
    with TestClient(app) as client:
        _, public_raw = _identity()
        grant = _admit(client, public_raw)
        response = client.post("/v2/turn", json={"grant": grant, "publicKeyHex": public_raw.hex()})
        assert response.status_code == 200
        payload = response.json()
        server = payload["iceServers"][0]
        assert server["username"].startswith(f"{payload['expiresAt']}:particle-")
        expected = base64.b64encode(hmac.new(
            b"turn-rest-secret", server["username"].encode("utf-8"), hashlib.sha1,
        ).digest()).decode("ascii")
        assert hmac.compare_digest(server["credential"], expected)
        assert server["urls"][0].startswith("turn:")


def test_turn_endpoint_has_independent_per_client_rate_limit():
    app = _app(
        turn_servers_json='[{"urls":"turns:turn.example:5349","username":"u","credential":"c"}]',
        turn_rate_burst=2,
        turn_rate_per_second=0.000001,
        turn_global_burst=10,
        turn_global_per_second=0.000001,
    )
    with TestClient(app) as client:
        _, public_raw = _identity()
        grant = _admit(client, public_raw)
        request = {"grant": grant, "publicKeyHex": public_raw.hex()}
        assert client.post("/v2/turn", json=request).status_code == 200
        assert client.post("/v2/turn", json=request).status_code == 200
        limited = client.post("/v2/turn", json=request)
        assert limited.status_code == 429 and limited.headers["retry-after"] == "1"


def test_admission_rate_limit_returns_retry_after():
    with TestClient(_app(admission_rate_burst=1, admission_rate_per_second=0.000001)) as client:
        _, public_raw = _identity()
        request = {
            "publicKeyHex": public_raw.hex(),
            "nonce": "0123456789abcdef",
            "protocol": PROTOCOL_VERSIONS["SESSION_V2"],
        }
        assert client.post("/v2/admission", json=request).status_code == 200
        limited = client.post("/v2/admission", json=request)
        assert limited.status_code == 429 and limited.headers["retry-after"] == "1"


def test_turn_rest_username_is_unlinkable_and_rotating_secret_is_selected():
    now = int(time.time())
    secrets_json = __import__("json").dumps([
        {"id": "old", "secret": "old-secret-material", "activatesAt": now - 100, "expiresAt": now + 100},
        {"id": "new", "secret": "new-secret-material", "activatesAt": now - 10, "expiresAt": now + 100},
    ])
    app = _app(
        turn_urls_json='["turn:turn.example:3478"]',
        turn_shared_secrets_json=secrets_json,
    )
    with TestClient(app) as client:
        _, public_raw = _identity()
        grant = _admit(client, public_raw)
        first = client.post("/v2/turn", json={"grant": grant, "publicKeyHex": public_raw.hex()}).json()
        second = client.post("/v2/turn", json={"grant": grant, "publicKeyHex": public_raw.hex()}).json()
        first_username = first["iceServers"][0]["username"]
        second_username = second["iceServers"][0]["username"]
        assert ":particle-new-" in first_username and first_username != second_username
        expected = base64.b64encode(hmac.new(
            b"new-secret-material", first_username.encode("utf-8"), hashlib.sha1,
        ).digest()).decode("ascii")
        assert hmac.compare_digest(first["iceServers"][0]["credential"], expected)


def test_admission_rejects_malformed_curve_point():
    with TestClient(_app()) as client:
        response = client.post("/v2/admission", json={
            "publicKeyHex": (b"\x04" + bytes(64)).hex(),
            "nonce": "0123456789abcdef",
            "protocol": PROTOCOL_VERSIONS["SESSION_V2"],
        })
        assert response.status_code == 400


def test_admission_limiter_cardinality_is_strictly_bounded():
    limiter = AdmissionLimiter(global_burst=10_000, global_refill=10_000)
    for index in range(5000):
        assert limiter.allow(f"client-{index}") is True
    assert len(limiter._buckets) == 4096
    assert "client-0" not in limiter._buckets


def test_admission_limiter_bounds_one_client_and_global_crypto_pressure():
    per_client = AdmissionLimiter(
        per_client_burst=2, per_client_refill=0.000001,
        global_burst=100, global_refill=0.000001,
    )
    assert per_client.allow("same-address") is True
    assert per_client.allow("same-address") is True
    assert per_client.allow("same-address") is False

    global_limit = AdmissionLimiter(
        per_client_burst=10, per_client_refill=0.000001,
        global_burst=2, global_refill=0.000001,
    )
    assert global_limit.allow("address-a") is True
    assert global_limit.allow("address-b") is True
    assert global_limit.allow("address-c") is False


def test_admission_rejects_duplicate_json_properties_before_crypto():
    with TestClient(_app()) as client:
        response = client.post(
            "/v2/admission",
            content=b'{"publicKeyHex":"00","publicKeyHex":"11","nonce":"0123456789abcdef","protocol":"particle-session/2"}',
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400


def test_v2_binary_application_frame_is_closed_with_unsupported_data():
    with TestClient(_app()) as client:
        with client.websocket_connect("/v2/ws") as ws:
            ws.send_bytes(b"{}")
            closed = ws.receive()
            assert closed["type"] == "websocket.close" and closed["code"] == 1003


def test_signed_manifest_can_disable_v2_advertisement_without_removing_v1():
    app = _app(advertise_v2=False)
    with TestClient(app) as client:
        manifest = client.get("/v2/manifest").json()["payload"]
        status = client.get("/status").json()
        assert manifest["protocols"] == ["particle-discovery/1"]
        assert manifest["endpoints"]["websocketV1"].endswith("/v1/ws")
        assert "websocketV2" not in manifest["endpoints"]
        assert "particle-session/2" not in status["protocols"]


def test_metrics_does_not_treat_a_forwarded_proxy_request_as_loopback():
    with TestClient(_app(), client=("127.0.0.1", 50000)) as client:
        response = client.get("/metrics", headers={"x-forwarded-for": "203.0.113.8"})
        assert response.status_code == 403


def test_v2_proof_attach_discover_directed_signal_and_replay_rejection():
    app = _app()
    route_tag = "a" * 64
    with TestClient(app) as client:
        private_a, public_a = _identity()
        private_b, public_b = _identity()
        with client.websocket_connect("/v2/ws") as ws_a, client.websocket_connect("/v2/ws") as ws_b:
            session_a = _prove(client, ws_a, private_a, public_a)
            session_b = _prove(client, ws_b, private_b, public_b)
            for ws in (ws_a, ws_b):
                ws.send_json({
                    "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "id": "attach",
                    "payload": {"routeTag": route_tag},
                })
                assert ws.receive_json()["payload"]["ok"] is True
            ws_a.send_json({
                "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "DISCOVER", "id": "discover",
                "payload": {"routeTag": route_tag},
            })
            peer = ws_a.receive_json()["payload"]["peers"][0]
            assert peer["sessionId"] == session_b and peer["encryptionKeyHex"] == public_b.hex()
            signal = {
                "protocol": PROTOCOL_VERSIONS["SIGNAL_V2"], "type": "SIGNAL", "id": "wire-signal",
                "payload": _signal_payload(
                    private_a, public_a, session_a, session_b, public_b, route_tag, "message-1",
                ),
            }
            ws_a.send_json(signal)
            delivered = ws_b.receive_json()
            assert delivered["type"] == "SIGNAL"
            assert delivered["payload"]["fromSessionId"] == session_a
            ack = ws_a.receive_json()
            assert ack["type"] == "SIGNAL_ACK" and ack["payload"]["delivered"] is True
            ws_a.send_json(signal)
            replay = ws_a.receive_json()
            assert replay["type"] == "ERROR" and replay["code"] == "replay"
            same_sequence = {**signal, "id": "wire-signal-2", "payload": {
                **signal["payload"], "messageId": "message-2",
            }}
            same_sequence["payload"]["signatureHex"] = _sign(
                private_a,
                canonical_json_bytes({
                    key: value for key, value in same_sequence["payload"].items() if key != "signatureHex"
                }),
            )
            ws_a.send_json(same_sequence)
            replay = ws_a.receive_json()
            assert replay["type"] == "ERROR" and replay["code"] == "replay"


def test_v2_forbids_cross_route_and_wrong_recipient_key_delivery():
    with TestClient(_app()) as client:
        private_a, public_a = _identity()
        private_b, public_b = _identity()
        with client.websocket_connect("/v2/ws") as ws_a, client.websocket_connect("/v2/ws") as ws_b:
            session_a = _prove(client, ws_a, private_a, public_a)
            session_b = _prove(client, ws_b, private_b, public_b)
            ws_a.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "id": "a", "payload": {"routeTag": "a" * 64}})
            ws_a.receive_json()
            ws_b.send_json({"protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "id": "b", "payload": {"routeTag": "b" * 64}})
            ws_b.receive_json()
            ws_a.send_json({
                "protocol": PROTOCOL_VERSIONS["SIGNAL_V2"], "type": "SIGNAL", "id": "cross",
                "payload": _signal_payload(
                    private_a, public_a, session_a, session_b, b"\x00" * 65, "a" * 64, "cross-route",
                ),
            })
            error = ws_a.receive_json()
            assert error["type"] == "ERROR" and error["code"] == "unknown-recipient"


def test_v2_discovery_requires_current_route_membership():
    route_tag = "c" * 64
    with TestClient(_app()) as client:
        private_a, public_a = _identity()
        private_b, public_b = _identity()
        with client.websocket_connect("/v2/ws") as ws_a, client.websocket_connect("/v2/ws") as ws_b:
            _prove(client, ws_a, private_a, public_a)
            _prove(client, ws_b, private_b, public_b)
            ws_b.send_json({
                "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "id": "attach-b",
                "payload": {"routeTag": route_tag},
            })
            assert ws_b.receive_json()["payload"]["ok"] is True
            ws_a.send_json({
                "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "DISCOVER", "id": "discover-a",
                "payload": {"routeTag": route_tag},
            })
            denied = ws_a.receive_json()
            assert denied["type"] == "ERROR" and denied["code"] == "not-attached"


def test_proven_v2_session_cannot_restart_the_proof_state_machine():
    with TestClient(_app()) as client:
        private_key, public_raw = _identity()
        with client.websocket_connect("/v2/ws") as ws:
            _prove(client, ws, private_key, public_raw)
            grant = _admit(client, public_raw)
            ws.send_json({
                "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "HELLO", "id": "hello-again",
                "payload": {
                    "grant": grant,
                    "identityKeyHex": public_raw.hex(),
                    "encryptionKeyHex": public_raw.hex(),
                },
            })
            response = ws.receive_json()
            assert response["type"] == "ERROR" and response["code"] == "invalid-state"


def test_silent_v2_client_hits_independent_proof_deadline():
    with TestClient(_app(proof_deadline_seconds=0.02)) as client:
        with client.websocket_connect("/v2/ws") as ws:
            error = ws.receive_json()
            assert error["type"] == "ERROR" and error["code"] == "proof-timeout"


def test_v2_closes_after_three_failed_proof_verifications():
    with TestClient(_app()) as client:
        _, public_raw = _identity()
        grant = _admit(client, public_raw)
        with client.websocket_connect("/v2/ws") as ws:
            ws.send_json({
                "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "HELLO", "id": "hello",
                "payload": {
                    "grant": grant,
                    "identityKeyHex": public_raw.hex(),
                    "encryptionKeyHex": public_raw.hex(),
                },
            })
            assert ws.receive_json()["type"] == "CHALLENGE"
            for index in range(3):
                ws.send_json({
                    "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "PROVE", "id": f"bad-{index}",
                    "payload": {"signatureHex": "00" * 64},
                })
                assert ws.receive_json()["code"] == "prove-failed"
            ws.send_json({
                "protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "PROVE", "id": "blocked",
                "payload": {"signatureHex": "00" * 64},
            })
            assert ws.receive_json()["code"] == "rate-limited"


def test_global_signal_bucket_rejects_before_more_signature_work():
    app = _app(signal_global_burst=2, signal_global_per_second=0.000001)
    route_tag = "e" * 64
    with TestClient(app) as client:
        private_key, public_raw = _identity()
        with client.websocket_connect("/v2/ws") as ws:
            session_id = _prove(client, ws, private_key, public_raw)
            ws.send_json({
                "protocol": PROTOCOL_VERSIONS["ROUTE_V2"], "type": "ATTACH_ROUTE", "id": "attach",
                "payload": {"routeTag": route_tag},
            })
            ws.receive_json()
            for sequence in range(3):
                payload = _signal_payload(
                    private_key, public_raw, session_id, "missing-session", b"\x04" + bytes(64),
                    route_tag, f"global-{sequence}",
                )
                payload["sequence"] = sequence
                payload["signatureHex"] = "00" * 64
                ws.send_json({
                    "protocol": PROTOCOL_VERSIONS["SIGNAL_V2"], "type": "SIGNAL",
                    "id": f"global-{sequence}", "payload": payload,
                })
                response = ws.receive_json()
                assert response["code"] == ("bad-signal-signature" if sequence < 2 else "capacity")


def test_global_message_bucket_sheds_before_additional_json_dispatch():
    app = _app(message_global_burst=3, message_global_per_second=0.000001)
    with TestClient(app) as client:
        private_key, public_raw = _identity()
        with client.websocket_connect("/v2/ws") as ws:
            _prove(client, ws, private_key, public_raw)
            ping = {"protocol": PROTOCOL_VERSIONS["SESSION_V2"], "type": "PING", "id": "ping"}
            ws.send_json(ping)
            assert ws.receive_json()["type"] == "PONG"
            ws.send_json({**ping, "id": "overflow"})
            response = ws.receive_json()
            assert response["type"] == "ERROR" and response["code"] == "capacity"


def test_v2_wrong_namespace_fails_closed():
    with TestClient(_app()) as client:
        with client.websocket_connect("/v2/ws") as ws:
            ws.send_json({"protocol": PROTOCOL_VERSIONS["SIGNAL_V2"], "type": "HELLO", "id": "bad", "payload": {}})
            error = ws.receive_json()
            assert error["type"] == "ERROR" and error["code"] in {"wrong-namespace", "bad-grant"}
