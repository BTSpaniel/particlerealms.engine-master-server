# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Generate a production P-256 node signing key and print its client pin."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a Particle v2 node signing key")
    parser.add_argument("--output", required=True, type=Path, help="private PEM output path; must not already exist")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error(f"refusing to overwrite existing key: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
        handle.flush()
        os.fsync(handle.fileno())
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    print(f"key_file={output}")
    print(f"server_key_pin={hashlib.sha256(public_raw).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
