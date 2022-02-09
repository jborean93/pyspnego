# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re

import pytest

from spnego._ntlm_raw.crypto import (
    RC4Handle,
    compute_response_v1,
    lmowfv1,
    ntowfv1,
    rc4init,
    sealkey,
    signkey,
)
from spnego._ntlm_raw.messages import NegotiateFlags
from spnego._ntlm_raw.security import seal, sign
from spnego._text import to_bytes
from spnego.exceptions import OperationNotAvailableError

from .._ntlm_raw import (
    TEST_CLIENT_CHALLENGE,
    TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS,
    TEST_NTLMV1_FLAGS,
    TEST_PASSWD,
    TEST_RANDOM_SESSION_KEY,
    TEST_SERVER_CHALLENGE,
)


def test_seal_ntlmv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/9e2b483e-d185-4feb-aa4f-db6e2c0c49d9
    seal_key = sealkey(TEST_NTLMV1_FLAGS, TEST_RANDOM_SESSION_KEY, usage="initiate")
    seal_handle = rc4init(seal_key)
    sign_key = signkey(TEST_NTLMV1_FLAGS, TEST_RANDOM_SESSION_KEY, usage="initiate") or b""

    b_data = to_bytes("Plaintext", encoding="utf-16-le")
    actual_msg, actual_signature = seal(TEST_NTLMV1_FLAGS, seal_handle, sign_key, 0, b_data)

    assert actual_msg == b"\x56\xFE\x04\xD8\x61\xF9\x31\x9A\xF0\xD7\x23\x8A\x2E\x3B\x4D\x45" b"\x7F\xB8"

    # The docs example seems to keep the random pad in the signature even though the actual function definition sets
    # that to 0x00000000. Assert the actual working implementation that has been tested against MS servers.
    assert actual_signature == b"\x01\x00\x00\x00\x00\x00\x00\x00\x09\xDC\xD1\xDF\x2E\x45\x9D\x36"


def test_seal_ntlmv1_with_ess():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/052aef59-b55b-4800-b4a8-e93eca1600d6
    key_exchange_key = compute_response_v1(
        TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS,
        ntowfv1(TEST_PASSWD),
        lmowfv1(TEST_PASSWD),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
    )[2]
    seal_key = sealkey(TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS, key_exchange_key, usage="initiate")
    seal_handle = rc4init(seal_key)
    sign_key = signkey(TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS, key_exchange_key, usage="initiate") or b""

    b_data = to_bytes("Plaintext", encoding="utf-16-le")
    actual_msg, actual_signature = seal(TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS, seal_handle, sign_key, 0, b_data)

    assert actual_msg == b"\xA0\x23\x72\xF6\x53\x02\x73\xF3\xAA\x1E\xB9\x01\x90\xCE\x52\x00" b"\xC9\x9D"
    assert actual_signature == b"\x01\x00\x00\x00\xFF\x2A\xEB\x52\xF6\x81\x79\x3A\x00\x00\x00\x00"


def test_seal_ntlmv2():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/54973495-20d2-49e8-9925-c399a403ed4a
    flags = (
        NegotiateFlags.seal
        | NegotiateFlags.sign
        | NegotiateFlags.extended_session_security
        | NegotiateFlags.key_exch
        | NegotiateFlags.key_128
    )

    seal_key = sealkey(flags, TEST_RANDOM_SESSION_KEY, usage="initiate")
    seal_handle = rc4init(seal_key)
    sign_key = signkey(flags, TEST_RANDOM_SESSION_KEY, usage="initiate") or b""

    b_data = to_bytes("Plaintext", encoding="utf-16-le")
    actual_msg, actual_signature = seal(flags, seal_handle, sign_key, 0, b_data)

    assert actual_msg == b"\x54\xE5\x01\x65\xBF\x19\x36\xDC\x99\x60\x20\xC1\x81\x1B\x0F\x06" b"\xFB\x5F"
    assert actual_signature == b"\x01\x00\x00\x00\x7F\xB3\x8E\xC5\xC5\x5D\x49\x76\x00\x00\x00\x00"


def test_seal_ntlmv2_no_key_exch():
    flags = (
        NegotiateFlags.seal | NegotiateFlags.sign | NegotiateFlags.extended_session_security | NegotiateFlags.key_128
    )

    seal_key = sealkey(flags, TEST_RANDOM_SESSION_KEY, usage="initiate")
    seal_handle = rc4init(seal_key)
    sign_key = signkey(flags, TEST_RANDOM_SESSION_KEY, usage="initiate") or b""

    b_data = to_bytes("Plaintext", encoding="utf-16-le")
    actual_msg, actual_signature = seal(flags, seal_handle, sign_key, 0, b_data)

    assert actual_msg == b"\x54\xE5\x01\x65\xBF\x19\x36\xDC\x99\x60\x20\xC1\x81\x1B\x0F\x06" b"\xFB\x5F"
    assert actual_signature == b"\x01\x00\x00\x00\x70\x35\x28\x51\xF2\x56\x43\x09\x00\x00\x00\x00"


def test_sign_with_always_sign():
    actual = sign(NegotiateFlags.always_sign, RC4Handle(b"\x00" * 16), b"", 0, b"data")

    assert actual == b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_sign_no_integrity():
    expected = "SpnegoError (16): Operation not supported or available, Context: Signing without integrity."

    with pytest.raises(OperationNotAvailableError, match=re.escape(expected)):
        sign(0, RC4Handle(b"\x00" * 16), b"", 0, b"data")
