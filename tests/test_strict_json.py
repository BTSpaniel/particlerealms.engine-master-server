# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

import pytest

from app.strict_json import StrictJsonError, loads_strict


@pytest.mark.parametrize("raw", [
    '{"key":1,"key":2}',
    '{"value":NaN}',
    '{"value":Infinity}',
    '{"value":-Infinity}',
])
def test_strict_json_rejects_ambiguous_or_non_finite_input(raw):
    with pytest.raises(StrictJsonError):
        loads_strict(raw, max_bytes=1024)


def test_strict_json_rejects_depth_nodes_and_string_limits():
    with pytest.raises(StrictJsonError):
        loads_strict('[[[[[0]]]]]', max_bytes=1024, max_depth=4)
    with pytest.raises(StrictJsonError):
        loads_strict('[1,2,3,4]', max_bytes=1024, max_nodes=4)
    with pytest.raises(StrictJsonError):
        loads_strict('{"value":"12345"}', max_bytes=1024, max_string_bytes=4)


def test_strict_json_accepts_a_small_unique_document():
    assert loads_strict('{"ok":true,"items":[1,2]}', max_bytes=1024) == {"ok": True, "items": [1, 2]}
