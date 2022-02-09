# -*- coding: utf-8 -*-
# (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from spnego._text import to_text

SKIP = False
try:
    import spnego._sspi_raw.text as text
except ImportError:
    SKIP = True


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
@pytest.mark.parametrize(
    "string, expected",
    [
        (None, 0),
        ("", 0),
        ("cafe", 5),
        ("café", 5),
        (to_text(b"\xF0\x9D\x84\x9E"), 3),  # Surrogate pair + null char
    ],
)
def test_wide_char(string, expected):
    wide_char = text.WideChar.from_text(string)

    assert len(wide_char) == expected
    assert wide_char.to_text() == (string or "")
