import hashlib
import os
import random

import pytest

from spnego._ntlm_raw.md4 import md4

HASHLIB_AVAIL = True
try:
    hashlib.new("md4")
except ValueError:
    HASHLIB_AVAIL = False


# The expectations here are based on the MD4 RFC
# https://datatracker.ietf.org/doc/html/rfc1320#appendix-A.5
@pytest.mark.parametrize(
    "data, expected",
    [
        (
            b"",
            b"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0",
        ),
        (
            b"a",
            b"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24",
        ),
        (
            b"abc",
            b"\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d",
        ),
        (
            b"message digest",
            b"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            b"\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            b"\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36",
        ),
    ],
)
def test_md4(data: bytes, expected: bytes) -> None:
    actual = md4(data)
    assert actual == expected


# This test will only run on hosts where md4 is still available on hashlib.
# It's just an extra sanity check to verify our implementation is still good.
@pytest.mark.skipif(not HASHLIB_AVAIL, reason="hashlib does not support md4")
def test_md4_to_hashlib() -> None:
    for idx in range(20):
        data = os.urandom(random.randint(idx * 10, (idx * 10) + 1024))

        expected = hashlib.new("md4", data).digest()
        actual = md4(data)

        assert actual == expected
