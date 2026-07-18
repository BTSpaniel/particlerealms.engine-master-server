# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

from app.config import Config
from app.trust import NodeTrust, parse_signed_manifest


def test_manifest_is_signed_pinned_and_stable_inside_validity_window():
    trust = NodeTrust(Config(node_id="node-a"))
    first = trust.manifest()
    second = trust.manifest()
    assert first == second
    valid, payload = parse_signed_manifest(first, trust.key_id)
    assert valid is True
    assert payload["nodeId"] == "node-a"
    assert parse_signed_manifest(first, "0" * 64) == (False, None)


def test_admission_is_bound_to_identity_and_expiry():
    trust = NodeTrust(Config(node_id="node-a", admission_ttl_seconds=30))
    public_key = trust.public_key_raw.hex()
    grant = trust.issue_admission(public_key, "0123456789abcdef", now=100)
    assert trust.verify_admission(grant, public_key, now=115) is True
    assert trust.verify_admission(grant, public_key, now=131) is False
    other = NodeTrust(Config()).public_key_raw.hex()
    assert trust.verify_admission(grant, other, now=115) is False
