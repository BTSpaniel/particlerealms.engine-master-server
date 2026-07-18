# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Short-lived TURN REST credentials bound to an admitted client identity."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from .config import Config


class TurnCredentialIssuer:
    def __init__(self, config: Config):
        self.config = config

    def issue(self, public_key_hex: str, now: int | None = None) -> dict:
        current = int(time.time() if now is None else now)
        expires_at = current + self.config.turn_ttl_seconds
        secret_id, shared_secret = _active_shared_secret(self.config, current)
        if shared_secret:
            urls = _turn_urls(self.config.turn_urls_json)
            prefix = _safe_prefix(self.config.turn_username_prefix)
            username = f"{expires_at}:{prefix}-{secret_id}-{secrets.token_hex(12)}"
            digest = hmac.new(
                shared_secret.encode("utf-8"),
                username.encode("utf-8"),
                hashlib.sha1,
            ).digest()
            credential = base64.b64encode(digest).decode("ascii")
            return {
                "iceServers": [{"urls": urls, "username": username, "credential": credential}],
                "expiresAt": expires_at,
            }

        try:
            servers = json.loads(self.config.turn_servers_json)
        except json.JSONDecodeError as exc:
            raise ValueError("static TURN configuration is invalid JSON") from exc
        if not valid_ice_servers(servers):
            raise ValueError("TURN is unavailable")
        return {"iceServers": servers, "expiresAt": expires_at}


def _active_shared_secret(config: Config, now: int) -> tuple[str, str]:
    try:
        entries = json.loads(config.turn_shared_secrets_json)
    except json.JSONDecodeError as exc:
        raise ValueError("PARTICLE_TURN_SHARED_SECRETS_JSON is invalid JSON") from exc
    if not isinstance(entries, list) or len(entries) > 8:
        raise ValueError("PARTICLE_TURN_SHARED_SECRETS_JSON must contain at most eight entries")
    active: list[tuple[int, str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "secret", "activatesAt", "expiresAt"}:
            raise ValueError("TURN shared-secret entries have invalid fields")
        key_id = entry["id"]
        secret = entry["secret"]
        activates_at = entry["activatesAt"]
        expires_at = entry["expiresAt"]
        if (
            not isinstance(key_id, str) or not 1 <= len(key_id) <= 16
            or not all(character.isalnum() or character in "-_" for character in key_id)
            or not isinstance(secret, str) or len(secret) < 16
            or not isinstance(activates_at, int) or isinstance(activates_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
        ):
            raise ValueError("TURN shared-secret entry is invalid")
        if activates_at <= now <= expires_at:
            active.append((activates_at, key_id, secret))
    if active:
        _, key_id, secret = max(active)
        return key_id, secret
    if config.turn_shared_secret:
        return "legacy", config.turn_shared_secret
    return "", ""


def _turn_urls(raw: str) -> list[str]:
    try:
        urls = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("PARTICLE_TURN_URLS_JSON is invalid JSON") from exc
    if not isinstance(urls, list) or not 1 <= len(urls) <= 16:
        raise ValueError("PARTICLE_TURN_URLS_JSON must contain 1 to 16 URLs")
    if not all(isinstance(url, str) and url.startswith(("turn:", "turns:")) for url in urls):
        raise ValueError("TURN URLs must use turn: or turns:")
    return urls


def _safe_prefix(value: str) -> str:
    if not value or len(value) > 32 or not all(ch.isalnum() or ch in "-_" for ch in value):
        raise ValueError("PARTICLE_TURN_USERNAME_PREFIX is invalid")
    return value


def valid_ice_servers(value) -> bool:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        return False
    for server in value:
        if not isinstance(server, dict) or set(server) != {"urls", "username", "credential"}:
            return False
        urls = server.get("urls")
        entries = urls if isinstance(urls, list) else [urls]
        if not entries or not all(isinstance(url, str) and url.startswith(("turn:", "turns:")) for url in entries):
            return False
        if not isinstance(server.get("username"), str) or not isinstance(server.get("credential"), str):
            return False
    return True
