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
}

KNOWN_PROTOCOLS = set(PROTOCOL_VERSIONS.values())

MESSAGE_TYPES = {
    "HELLO", "PROVE", "ATTACH_ROUTE", "DETACH_ROUTE", "SUBSCRIBE", "UNSUBSCRIBE",
    "DISCOVER", "PEERS", "PUBLISH", "FORWARD", "SIGNAL", "PING", "PONG", "ERROR",
}


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
    protocol = data.get("protocol")
    msg_type = data.get("type")
    if protocol not in KNOWN_PROTOCOLS:
        raise ProtocolError("unknown-protocol", f"unknown/unversioned protocol namespace: {protocol!r}")
    if msg_type not in MESSAGE_TYPES:
        raise ProtocolError("unknown-type", f"unknown message type: {msg_type!r}")


def make_error(code: str, message: str, in_reply_to: str | None = None) -> dict:
    return {
        "protocol": PROTOCOL_VERSIONS["SESSION"],
        "type": "ERROR",
        "code": code,
        "message": message,
        "inReplyTo": in_reply_to,
    }
