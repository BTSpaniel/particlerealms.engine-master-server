# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Signed node manifests and short-lived admission grants for protocol v2."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils

from .canonical import canonical_json_bytes
from .config import Config
from .session_crypto import verify_signature


def _raw_signature(private_key, payload: bytes) -> bytes:
    der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = ec_utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class NodeTrust:
    def __init__(self, config: Config):
        self.config = config
        self.private_key = self._load_private_key()
        self.public_key_raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.key_id = hashlib.sha256(self.public_key_raw).hexdigest()
        self.started_at = int(time.time())
        if not self.config.signing_key_activates_at <= self.started_at <= self.config.signing_key_expires_at:
            raise RuntimeError("configured node signing key is outside its activation window")
        self._manifest: dict | None = None

    def _load_private_key(self):
        pem = self.config.signing_key_pem.encode("utf-8") if self.config.signing_key_pem else b""
        if not pem and self.config.signing_key_file:
            pem = Path(self.config.signing_key_file).read_bytes()
        if pem:
            key = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ValueError("PARTICLE signing key must be an unencrypted P-256 EC private key")
            return key
        if self.config.require_configured_signing_key:
            raise RuntimeError("production requires PARTICLE_SIGNING_KEY_PEM or PARTICLE_SIGNING_KEY_FILE")
        return ec.generate_private_key(ec.SECP256R1())

    def sign_object(self, payload: dict) -> dict:
        signature = _raw_signature(self.private_key, canonical_json_bytes(payload))
        return {"payload": payload, "keyId": self.key_id, "signatureHex": signature.hex()}

    def verify_signed_object(self, signed: dict, expected_key_raw: bytes | None = None) -> bool:
        if (
            not isinstance(signed, dict)
            or set(signed) != {"payload", "keyId", "signatureHex"}
            or not isinstance(signed.get("payload"), dict)
            or not isinstance(signed.get("keyId"), str)
            or signed.get("keyId") != hashlib.sha256(expected_key_raw or self.public_key_raw).hexdigest()
        ):
            return False
        try:
            signature = bytes.fromhex(signed.get("signatureHex", ""))
        except (TypeError, ValueError):
            return False
        key = expected_key_raw or self.public_key_raw
        return len(signature) == 64 and verify_signature(key, canonical_json_bytes(signed["payload"]), signature)

    def manifest(self, now: int | None = None) -> dict:
        issued_at = int(time.time() if now is None else now)
        if now is None and self._manifest is not None:
            expires_at = self._manifest["payload"]["expiresAt"]
            if issued_at < expires_at - 60:
                return self._manifest
        protocols = ["particle-discovery/1"]
        endpoints = {
            "http": self.config.public_base_url.rstrip("/"),
            "websocketV1": self.config.public_v1_ws_url,
        }
        if self.config.advertise_v2:
            protocols.extend(["particle-session/2", "particle-route/2", "particle-signal/2"])
            endpoints["websocketV2"] = self.config.public_ws_url
        if self.config.node_mesh_enabled:
            protocols.append("particle-node/1")
            endpoints["nodeMesh"] = self.config.public_node_ws_url
        payload = {
            "format": "particle-node-manifest/2",
            "nodeId": self.config.node_id,
            "networkRootId": self.config.network_root_id,
            "networkRootVersion": self.config.network_root_version,
            "networkRootRollbackVersion": self.config.network_root_rollback_version,
            "protocols": protocols,
            "endpoints": endpoints,
            "signingPublicKeyHex": self.public_key_raw.hex(),
            "signingKeyId": self.key_id,
            "signingKeyValidity": {
                "activatesAt": self.config.signing_key_activates_at,
                "expiresAt": self.config.signing_key_expires_at,
            },
            "issuedAt": issued_at,
            "expiresAt": issued_at + self.config.manifest_ttl_seconds,
        }
        signed = self.sign_object(payload)
        if now is None:
            self._manifest = signed
        return signed

    def manifest_hash(self, manifest: dict | None = None) -> str:
        return hashlib.sha256(canonical_json_bytes(manifest or self.manifest())).hexdigest()

    def issue_admission(self, public_key_hex: str, nonce: str, now: int | None = None) -> dict:
        issued_at = int(time.time() if now is None else now)
        claims = {
            "format": "particle-admission/2",
            "issuer": self.config.node_id,
            "keyHash": hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest(),
            "nonceHash": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            "protocol": "particle-session/2",
            "issuedAt": issued_at,
            "expiresAt": issued_at + self.config.admission_ttl_seconds,
        }
        return self.sign_object(claims)

    def verify_admission(self, grant: dict, public_key_hex: str, now: int | None = None) -> bool:
        if not self.verify_signed_object(grant):
            return False
        claims = grant["payload"]
        if set(claims) != {"format", "issuer", "keyHash", "nonceHash", "protocol", "issuedAt", "expiresAt"}:
            return False
        current = int(time.time() if now is None else now)
        try:
            key_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
        except (TypeError, ValueError):
            return False
        return (
            claims.get("format") == "particle-admission/2"
            and claims.get("issuer") == self.config.node_id
            and claims.get("protocol") == "particle-session/2"
            and hmac.compare_digest(str(claims.get("keyHash", "")), key_hash)
            and isinstance(claims.get("nonceHash"), str) and len(claims["nonceHash"]) == 64
            and isinstance(claims.get("issuedAt"), int) and not isinstance(claims.get("issuedAt"), bool)
            and isinstance(claims.get("expiresAt"), int) and not isinstance(claims.get("expiresAt"), bool)
            and claims["issuedAt"] <= current <= claims["expiresAt"]
        )


def parse_signed_manifest(value: dict, expected_pin: str) -> tuple[bool, dict | None]:
    """Verify a foreign manifest against an explicit SHA-256 public-key pin."""
    try:
        if set(value) != {"payload", "keyId", "signatureHex"}:
            return False, None
        payload = value["payload"]
        if set(payload) != {
            "format", "nodeId", "networkRootId", "networkRootVersion", "networkRootRollbackVersion",
            "protocols", "endpoints", "signingPublicKeyHex", "signingKeyId", "signingKeyValidity",
            "issuedAt", "expiresAt",
        }:
            return False, None
        raw_key = bytes.fromhex(payload["signingPublicKeyHex"])
        signature = bytes.fromhex(value["signatureHex"])
        pin = hashlib.sha256(raw_key).hexdigest()
        key_validity = payload["signingKeyValidity"]
        activates_at = key_validity["activatesAt"]
        expires_at = key_validity["expiresAt"]
    except (KeyError, TypeError, ValueError):
        return False, None
    now = int(time.time())
    valid = (
        hmac.compare_digest(pin, expected_pin.lower())
        and value.get("keyId") == pin
        and payload.get("signingKeyId") == pin
        and payload.get("format") == "particle-node-manifest/2"
        and isinstance(activates_at, int)
        and not isinstance(activates_at, bool)
        and isinstance(expires_at, int)
        and not isinstance(expires_at, bool)
        and activates_at <= now <= expires_at
        and verify_signature(raw_key, canonical_json_bytes(payload), signature)
    )
    return valid, payload if valid else None
