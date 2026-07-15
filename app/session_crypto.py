# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""
Masterserver/app/session_crypto.py — session proof, not identity ownership
(network plan §12): the server verifies "this socket controls this
temporary session key" via a HELLO challenge + PROVE signature, using the
SAME ECDSA P-256 keys the JS client already generates
(engine/collab/CollabIdentity.js, exposed via engine/network/identity).

Web Crypto's `{name:'ECDSA', hash:'SHA-256'}` signatures are raw IEEE P1363
format (64 bytes: 32-byte r || 32-byte s) — NOT the ASN.1 DER format
`cryptography`'s ec.ECDSA verifier expects by default. This module converts
between the two so a real browser client's signature verifies correctly
here.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils


def generate_challenge() -> bytes:
    return os.urandom(32)


def _load_public_key(raw_point: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_point)


def verify_signature(public_key_raw: bytes, message: bytes, signature_raw: bytes) -> bool:
    """
    Verify a raw P1363 (r||s) ECDSA P-256 signature over `message`.
    Fails closed (returns False) on any malformed input rather than raising.
    """
    if not public_key_raw or not signature_raw or len(signature_raw) != 64:
        return False
    try:
        r = int.from_bytes(signature_raw[:32], "big")
        s = int.from_bytes(signature_raw[32:], "big")
        der_signature = ec_utils.encode_dss_signature(r, s)
        public_key = _load_public_key(public_key_raw)
        public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        # Fail closed on any unexpected malformed-key/point error too.
        return False
