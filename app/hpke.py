# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""RFC 9180 base-mode HPKE suite P-256/HKDF-SHA256/AES-128-GCM.

The masterserver never decrypts signaling. This implementation exists for
protocol interoperability tests and the Python mesh release harness.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEM_ID = 0x0010
KDF_ID = 0x0001
AEAD_ID = 0x0001
KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE_ID = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), ikm, sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), sha256).digest()
        output += previous
    return output[:length]


def _labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _serialize_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _deserialize_public(raw: bytes):
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("HPKE P-256 public key must be a 65-byte uncompressed point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def _dhkem_shared_secret(dh: bytes, enc: bytes, recipient_public_raw: bytes) -> bytes:
    kem_context = enc + recipient_public_raw
    eae_prk = _labeled_extract(b"", KEM_SUITE_ID, b"eae_prk", dh)
    return _labeled_expand(eae_prk, KEM_SUITE_ID, b"shared_secret", kem_context, 32)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(b"", HPKE_SUITE_ID, b"psk_id_hash", b"")
    info_hash = _labeled_extract(b"", HPKE_SUITE_ID, b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, HPKE_SUITE_ID, b"secret", b"")
    key = _labeled_expand(secret, HPKE_SUITE_ID, b"key", context, 16)
    base_nonce = _labeled_expand(secret, HPKE_SUITE_ID, b"base_nonce", context, 12)
    return key, base_nonce


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, _serialize_public(private_key.public_key())


def seal(
    recipient_public_raw: bytes,
    plaintext: bytes,
    *,
    info: bytes = b"particle-signal/2",
    aad: bytes = b"",
    ephemeral_private_key=None,
) -> tuple[bytes, bytes]:
    recipient_public = _deserialize_public(recipient_public_raw)
    ephemeral = ephemeral_private_key or ec.generate_private_key(ec.SECP256R1())
    enc = _serialize_public(ephemeral.public_key())
    dh = ephemeral.exchange(ec.ECDH(), recipient_public)
    shared_secret = _dhkem_shared_secret(dh, enc, recipient_public_raw)
    key, nonce = _key_schedule(shared_secret, info)
    return enc, AESGCM(key).encrypt(nonce, plaintext, aad)


def open_message(
    recipient_private_key,
    enc: bytes,
    ciphertext: bytes,
    *,
    info: bytes = b"particle-signal/2",
    aad: bytes = b"",
) -> bytes:
    ephemeral_public = _deserialize_public(enc)
    recipient_public_raw = _serialize_public(recipient_private_key.public_key())
    dh = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
    shared_secret = _dhkem_shared_secret(dh, enc, recipient_public_raw)
    key, nonce = _key_schedule(shared_secret, info)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
