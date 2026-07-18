# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Deterministic JSON for signatures, manifests, and dedupe keys.

Every cross-runtime signed schema is restricted to objects, arrays, strings,
booleans, and safe integer epoch/sequence values. Under that deliberately
small domain this encoding byte-matches ``Trust.js``: sorted object keys,
UTF-8 text, and no insignificant whitespace. Floats are never accepted in a
signed wire schema.
"""

import hashlib
import json


def canonical_json_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash_hex(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
