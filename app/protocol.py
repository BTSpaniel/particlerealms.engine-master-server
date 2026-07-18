# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/protocol.py — the tiny, versioned wire protocol (network
plan §7/§34/§43). Mirrors the namespace strings used by the JS client
(engine/network/protocol.js PROTOCOL_VERSIONS) so both sides speak the same
language, but this server never trusts the client's protocol claim beyond
routing — payload verification always happens end-to-end between peers, not
here (network plan §12).
"""

from __future__ import annotations

PROTOCOL_VERSIONS = {
    "DISCOVERY": "particle-discovery/1",
    "SESSION": "particle-session/1",
    "ROUTE": "particle-route/1",
    "SIGNAL": "particle-signal/1",
    "SESSION_V2": "particle-session/2",
    "ROUTE_V2": "particle-route/2",
    "SIGNAL_V2": "particle-signal/2",
    "NODE": "particle-node/1",
}

KNOWN_PROTOCOLS = set(PROTOCOL_VERSIONS.values())

MESSAGE_TYPES = {
    "HELLO", "PROVE", "ATTACH_ROUTE", "DETACH_ROUTE", "SUBSCRIBE", "UNSUBSCRIBE",
    "DISCOVER", "PEERS", "PUBLISH", "FORWARD", "SIGNAL", "PING", "PONG", "ERROR",
    "CHALLENGE", "SESSION_READY", "SIGNAL_ACK",
    "NODE_HELLO", "NODE_STATE", "ROUTE_REGISTER", "ROUTE_REMOVE", "ROUTE_QUERY",
    "ROUTE_RESULT", "SIGNAL_FORWARD", "ACK",
}

MAX_ID_BYTES = 128
MAX_ROUTE_ID_BYTES = 256
MAX_V2_ROUTE_TAG_BYTES = 64


class ProtocolError(Exception):
    """Raised for malformed/unversioned/unknown inbound messages (fail closed)."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def validate_envelope(data) -> None:
    """Reject anything that isn't a well-formed, known-protocol, known-type message."""
    if not isinstance(data, dict):
        raise ProtocolError("bad-envelope", "message must be a JSON object")
    unexpected = set(data) - {"protocol", "type", "id", "payload"}
    if unexpected:
        raise ProtocolError("bad-envelope", "message contains unexpected envelope fields")
    protocol = data.get("protocol")
    msg_type = data.get("type")
    if protocol not in KNOWN_PROTOCOLS:
        raise ProtocolError("unknown-protocol", f"unknown/unversioned protocol namespace: {protocol!r}")
    if msg_type not in MESSAGE_TYPES:
        raise ProtocolError("unknown-type", f"unknown message type: {msg_type!r}")
    message_id = data.get("id")
    if message_id is not None and (not isinstance(message_id, str) or not 1 <= len(message_id.encode("utf-8")) <= MAX_ID_BYTES):
        raise ProtocolError("bad-id", "message id must be bounded UTF-8 text")
    if "payload" in data and data["payload"] is not None and not isinstance(data["payload"], dict):
        raise ProtocolError("bad-payload", "payload must be a JSON object")


def bounded_text(value, *, field: str, maximum: int, exact: int | None = None) -> str:
    if not isinstance(value, str):
        raise ProtocolError("bad-field", f"{field} must be text")
    size = len(value.encode("utf-8"))
    if size == 0 or size > maximum or (exact is not None and size != exact):
        expected = f"exactly {exact}" if exact is not None else f"1..{maximum}"
        raise ProtocolError("bad-field", f"{field} must contain {expected} UTF-8 bytes")
    return value


def validate_v1_message(data: dict) -> None:
    """Validate the fields the legacy endpoint actually consumes."""
    validate_envelope(data)
    payload = data.get("payload") or {}
    msg_type = data["type"]
    expected_protocol = {
        "HELLO": PROTOCOL_VERSIONS["SESSION"],
        "PROVE": PROTOCOL_VERSIONS["SESSION"],
        "PING": PROTOCOL_VERSIONS["SESSION"],
        "ATTACH_ROUTE": PROTOCOL_VERSIONS["ROUTE"],
        "DETACH_ROUTE": PROTOCOL_VERSIONS["ROUTE"],
        "DISCOVER": PROTOCOL_VERSIONS["ROUTE"],
        "SIGNAL": PROTOCOL_VERSIONS["SIGNAL"],
        "FORWARD": PROTOCOL_VERSIONS["SIGNAL"],
        "PUBLISH": PROTOCOL_VERSIONS["SIGNAL"],
    }.get(msg_type)
    # Early particle-discovery/1 clients use the discovery namespace for every
    # legacy message. Keep accepting that wire form while also accepting the
    # later per-operation v1 namespaces.
    if expected_protocol is None or data["protocol"] not in {PROTOCOL_VERSIONS["DISCOVERY"], expected_protocol}:
        raise ProtocolError("wrong-namespace", f"{msg_type} is not valid in protocol namespace {data['protocol']}")
    if msg_type == "HELLO":
        if set(payload) != {"publicKeyHex"}:
            raise ProtocolError("bad-payload", "HELLO requires only payload.publicKeyHex")
        _hex_field(payload["publicKeyHex"], "payload.publicKeyHex", 65)
    elif msg_type == "PROVE":
        if set(payload) != {"signatureHex"}:
            raise ProtocolError("bad-payload", "PROVE requires only payload.signatureHex")
        _hex_field(payload.get("signatureHex"), "payload.signatureHex", 64)
    elif msg_type == "PING" and payload:
        raise ProtocolError("bad-payload", "PING payload must be empty")
    elif msg_type in {"ATTACH_ROUTE", "DETACH_ROUTE", "DISCOVER", "SIGNAL", "FORWARD", "PUBLISH"}:
        bounded_text(payload.get("routeId"), field="payload.routeId", maximum=MAX_ROUTE_ID_BYTES)
        if msg_type in {"ATTACH_ROUTE", "DETACH_ROUTE", "DISCOVER"} and set(payload) != {"routeId"}:
            raise ProtocolError("bad-payload", f"{msg_type} requires only payload.routeId")
    if msg_type in {"SIGNAL", "FORWARD", "PUBLISH"}:
        ttl = payload.get("ttl")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or not 0 <= ttl <= 16):
            raise ProtocolError("bad-ttl", "payload.ttl must be an integer in 0..16")


def validate_v2_message(data: dict) -> None:
    validate_envelope(data)
    protocol = data["protocol"]
    if protocol not in {PROTOCOL_VERSIONS["SESSION_V2"], PROTOCOL_VERSIONS["ROUTE_V2"], PROTOCOL_VERSIONS["SIGNAL_V2"]}:
        raise ProtocolError("wrong-version", "v2 endpoint requires a v2 protocol namespace")
    payload = data.get("payload") or {}
    msg_type = data["type"]
    expected_protocol = {
        "HELLO": PROTOCOL_VERSIONS["SESSION_V2"],
        "PROVE": PROTOCOL_VERSIONS["SESSION_V2"],
        "PING": PROTOCOL_VERSIONS["SESSION_V2"],
        "ATTACH_ROUTE": PROTOCOL_VERSIONS["ROUTE_V2"],
        "DETACH_ROUTE": PROTOCOL_VERSIONS["ROUTE_V2"],
        "DISCOVER": PROTOCOL_VERSIONS["ROUTE_V2"],
        "SIGNAL": PROTOCOL_VERSIONS["SIGNAL_V2"],
    }.get(msg_type)
    if expected_protocol is None or protocol != expected_protocol:
        raise ProtocolError("wrong-namespace", f"{msg_type} is not valid in protocol namespace {protocol}")
    if msg_type == "HELLO":
        if set(payload) != {"grant", "identityKeyHex", "encryptionKeyHex"}:
            raise ProtocolError("bad-payload", "HELLO payload fields are invalid")
        if not isinstance(payload.get("grant"), dict):
            raise ProtocolError("bad-grant", "HELLO requires payload.grant")
        _hex_field(payload.get("identityKeyHex"), "payload.identityKeyHex", 65)
        _hex_field(payload.get("encryptionKeyHex"), "payload.encryptionKeyHex", 65)
    elif msg_type == "PROVE":
        if set(payload) != {"signatureHex"}:
            raise ProtocolError("bad-payload", "PROVE requires only payload.signatureHex")
        _hex_field(payload.get("signatureHex"), "payload.signatureHex", 64)
    elif msg_type == "PING" and payload:
        raise ProtocolError("bad-payload", "PING payload must be empty")
    elif msg_type in {"ATTACH_ROUTE", "DETACH_ROUTE", "DISCOVER", "SIGNAL"}:
        route_tag = bounded_text(payload.get("routeTag"), field="payload.routeTag", maximum=64, exact=64)
        if route_tag != route_tag.lower() or any(ch not in "0123456789abcdef" for ch in route_tag):
            raise ProtocolError("bad-route-tag", "payload.routeTag must be lowercase SHA-256 hex")
    if msg_type == "SIGNAL":
        if set(payload) != {
            "routeTag", "fromSessionId", "toSessionId", "messageId", "sequence", "expiresAt",
            "keyId", "senderKeyId", "senderIdentityKeyHex", "encHex", "ciphertextHex", "signatureHex",
        }:
            raise ProtocolError("bad-payload", "SIGNAL payload fields are invalid")
        bounded_text(payload.get("toSessionId"), field="payload.toSessionId", maximum=64)
        bounded_text(payload.get("fromSessionId"), field="payload.fromSessionId", maximum=64)
        bounded_text(payload.get("messageId"), field="payload.messageId", maximum=128)
        bounded_text(payload.get("keyId"), field="payload.keyId", maximum=128)
        bounded_text(payload.get("senderKeyId"), field="payload.senderKeyId", maximum=64, exact=64)
        _hex_field(payload.get("senderIdentityKeyHex"), "payload.senderIdentityKeyHex", 65)
        _hex_field(payload.get("encHex"), "payload.encHex", 65)
        _hex_field(payload.get("signatureHex"), "payload.signatureHex", 64)
        ciphertext = bounded_text(payload.get("ciphertextHex"), field="payload.ciphertextHex", maximum=96 * 1024)
        if len(ciphertext) % 2:
            raise ProtocolError("bad-field", "payload.ciphertextHex must have an even number of hex digits")
        try:
            bytes.fromhex(ciphertext)
        except ValueError as exc:
            raise ProtocolError("bad-field", "payload.ciphertextHex must be hexadecimal") from exc
        sequence = payload.get("sequence")
        expires_at = payload.get("expiresAt")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= 0xFFFFFFFF:
            raise ProtocolError("bad-sequence", "payload.sequence must be uint32")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ProtocolError("bad-expiry", "payload.expiresAt must be integer epoch seconds")
    elif msg_type in {"ATTACH_ROUTE", "DETACH_ROUTE", "DISCOVER"} and set(payload) != {"routeTag"}:
        raise ProtocolError("bad-payload", f"{msg_type} requires only payload.routeTag")


def _hex_field(value, field: str, byte_length: int) -> bytes:
    text = bounded_text(value, field=field, maximum=byte_length * 2, exact=byte_length * 2)
    try:
        decoded = bytes.fromhex(text)
    except ValueError as exc:
        raise ProtocolError("bad-field", f"{field} must be hexadecimal") from exc
    if len(decoded) != byte_length:
        raise ProtocolError("bad-field", f"{field} must encode {byte_length} bytes")
    return decoded


def make_error(code: str, message: str, in_reply_to: str | None = None) -> dict:
    return {
        "protocol": PROTOCOL_VERSIONS["SESSION"],
        "type": "ERROR",
        "code": code,
        "message": message,
        "inReplyTo": in_reply_to,
    }
