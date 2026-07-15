# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

from app.protocol import PROTOCOL_VERSIONS, ProtocolError, make_error, validate_envelope


def test_validate_envelope_accepts_known_protocol_and_type():
    validate_envelope({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "PING"})


def test_validate_envelope_rejects_unknown_protocol():
    try:
        validate_envelope({"protocol": "evil/1", "type": "PING"})
        assert False, "expected ProtocolError"
    except ProtocolError as exc:
        assert exc.code == "unknown-protocol"


def test_validate_envelope_rejects_unversioned_protocol():
    try:
        validate_envelope({"protocol": "particle-session", "type": "PING"})
        assert False, "expected ProtocolError"
    except ProtocolError as exc:
        assert exc.code == "unknown-protocol"


def test_validate_envelope_rejects_unknown_type():
    try:
        validate_envelope({"protocol": PROTOCOL_VERSIONS["SESSION"], "type": "NOT_A_TYPE"})
        assert False, "expected ProtocolError"
    except ProtocolError as exc:
        assert exc.code == "unknown-type"


def test_validate_envelope_rejects_non_dict():
    try:
        validate_envelope("not a dict")
        assert False, "expected ProtocolError"
    except ProtocolError as exc:
        assert exc.code == "bad-envelope"


def test_make_error_shape():
    err = make_error("some-code", "some message", in_reply_to="abc")
    assert err["type"] == "ERROR"
    assert err["code"] == "some-code"
    assert err["inReplyTo"] == "abc"
