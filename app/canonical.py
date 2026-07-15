# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/canonical.py — deterministic JSON serialization + content
hashing, used only for the internal dedupe cache key (network plan §29).
Does not need to byte-match the JS client's canonicalization (that matters
only where signatures cross the wire, and the server never verifies
peer-to-peer signatures — network plan §12) — it only needs to be
deterministic for THIS process's own dedupe decisions.
"""

import hashlib
import json


def canonical_json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash_hex(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
