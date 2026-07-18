<!--
SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>

SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha
-->

# Particle node trust and key rotation

Clients trust a node only when its signed `particle-node-manifest/2` verifies
against the `serverKeyPin` shipped in their masterserver list. A pin is the
lowercase SHA-256 digest of the node's 65-byte uncompressed P-256 public key.
There is no trust-on-first-use fallback and an integrity failure never retries
the same endpoint with protocol v1.

## Initial key

```bash
sudo install -d -m 0700 -o particle -g particle /etc/particle-masterserver
sudo -u particle /opt/particle-masterserver/.venv/bin/python \
  /opt/particle-masterserver/generate_signing_key.py \
  --output /etc/particle-masterserver/node-signing-key.pem
```

Copy the printed pin into the signed network-root configuration and client
masterserver list. Set `PARTICLE_REQUIRE_CONFIGURED_SIGNING_KEY=true`; an
ephemeral development key must never advertise a production endpoint.

## Rotation

1. Generate the replacement key offline and record both old and new pins.
2. Publish a signed network-root revision containing both `serverKeyPins`, an
   `activatesAt`, an `expiresAt`, and a monotonically increasing root version.
   Set the node's `PARTICLE_SIGNING_KEY_ACTIVATES_AT` and
   `PARTICLE_SIGNING_KEY_EXPIRES_AT` to the matching absolute epoch values.
3. Wait until that root revision is deployed to supported clients.
4. Stop the node, change `PARTICLE_SIGNING_KEY_FILE`, and restart it at or after
   the activation time.
5. Verify `/v2/manifest`, the new pin, admission, and a two-client mesh run.
6. After the overlap window, publish the next root revision removing the old
   pin. Never reuse a revision number or move an expiry backwards.

The browser daemon verifies the active pin entry, the signed manifest's key
activation window, root ID, root version, and authorized rollback version. It
also persists the highest accepted root, rollback, and issuance values and
fails closed if an endpoint later moves any of them backwards. The
masterserver mesh requires an exact configured root tuple and a pinned signing
key on every node connection.

## Emergency recovery and rollback

- If the new key fails before the old pin expires, restore the previous key and
  restart. `/v1/ws` remains the independent compatibility rollback path.
- If a key may be compromised, remove its pin in an offline-root-signed
  revision, disable v2 advertisement at the edge, and rotate immediately.
- Preserve the offline root key separately from online node keys. The service
  deliberately does not possess the offline root private key; threshold root
  signatures are release metadata distributed with the client configuration.
- Never place private keys, TURN credentials, metrics tokens, or mTLS keys in
  the repository, manifests, logs, or mesh evidence.

The node proxy-attestation token is also secret. Rotate it by placing a new
random 32-byte-or-longer value in both the installed nginx node-host config and
`PARTICLE_NODE_MESH_PROXY_TOKEN`, then reload nginx and restart the application
in one maintenance operation. Existing node sockets may reconnect; mismatched
or stale tokens fail before node-manifest parsing. Do not reuse this token as a
TURN, metrics, signing-key, or certificate secret.

The overlap, monotonic-version, expiry, and offline-root rules follow the
separation used by The Update Framework without importing a package manager
or remote federation service into Particle Network.
