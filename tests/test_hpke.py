# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import pytest

from app.hpke import generate_key_pair, open_message, seal


def test_rfc9180_suite_round_trip_and_aad_binding():
    private_key, public_raw = generate_key_pair()
    enc, ciphertext = seal(public_raw, b"encrypted offer", aad=b"route-context")
    assert len(enc) == 65
    assert len(ciphertext) == len(b"encrypted offer") + 16
    assert open_message(private_key, enc, ciphertext, aad=b"route-context") == b"encrypted offer"
    with pytest.raises(Exception):
        open_message(private_key, enc, ciphertext, aad=b"wrong-context")


def test_rfc9180_suite_rejects_tampered_ciphertext():
    private_key, public_raw = generate_key_pair()
    enc, ciphertext = seal(public_raw, b"candidate")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(Exception):
        open_message(private_key, enc, tampered)
