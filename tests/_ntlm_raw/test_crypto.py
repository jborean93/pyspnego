# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import os

import pytest

import spnego._ntlm_raw.crypto as crypto
from spnego._ntlm_raw.messages import FileTime, NegotiateFlags, TargetInfo
from spnego._text import to_text

from .._ntlm_raw import (
    TEST_CLIENT_CHALLENGE,
    TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS,
    TEST_NTLMV1_FLAGS,
    TEST_PASSWD,
    TEST_RANDOM_SESSION_KEY,
    TEST_SERVER_CHALLENGE,
    TEST_TIME,
    TEST_USER,
    TEST_USER_DOM,
)


def test_crc32():
    actual = crypto.crc32(b"123456789")

    # http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32
    assert actual == b"\x26\x39\xf4\xcb"


def test_lmowfv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a724e8df-2b0a-4a36-aef4-2d2b56fd3db7
    actual = crypto.lmowfv1(TEST_PASSWD)

    assert actual == b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"


def test_lmowfv1_hash():
    lm_hash = os.urandom(16)
    nt_hash = os.urandom(16)
    ntlm_hash = to_text(b"%s:%s" % (base64.b16encode(lm_hash), base64.b16encode(nt_hash)))

    actual = crypto.lmowfv1(ntlm_hash)

    assert actual == lm_hash


def test_ntowfv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/0fb94d19-16d2-481d-9121-112defbaac0b
    actual = crypto.ntowfv1(TEST_PASSWD)

    assert actual == b"\xa4\xf4\x9c\x40\x65\x10\xbd\xca\xb6\x82\x4e\xe7\xc3\x0f\xd8\x52"


def test_ntowfv1_hash():
    lm_hash = os.urandom(16)
    nt_hash = os.urandom(16)
    ntlm_hash = to_text(b"%s:%s" % (base64.b16encode(lm_hash), base64.b16encode(nt_hash)))

    actual = crypto.ntowfv1(ntlm_hash)

    assert actual == nt_hash


def test_compute_response_v1_no_session_security():
    actual_nt, actual_lm, actual_kek = crypto.compute_response_v1(
        TEST_NTLMV1_FLAGS,
        crypto.ntowfv1(TEST_PASSWD),
        crypto.lmowfv1(TEST_PASSWD),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a9dc740e-e12f-4fdd-8f2b-61a471731a14
    assert (
        actual_nt == b"\x67\xc4\x30\x11\xf3\x02\x98\xa2\xad\x35\xec\xe6\x4f\x16\x33\x1c"
        b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert actual_lm == actual_nt

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/0b344a44-7cd8-4ab5-b07c-ff2b3d8c15f4
    assert actual_kek == b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb\x74\x99\xbe\xcc\xcd\xf1\x07\x84"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x51\x88\x22\xb1\xb3\xf3\x50\xc8\x95\x86\x82\xec\xbb\x3e\x3c\xb7"


def test_compute_response_v1_no_session_security_non_nt_key():
    flags = TEST_NTLMV1_FLAGS | NegotiateFlags.non_nt_session_key
    actual_nt, actual_lm, actual_kek = crypto.compute_response_v1(
        flags,
        crypto.ntowfv1(TEST_PASSWD),
        crypto.lmowfv1(TEST_PASSWD),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
        no_lm_response=False,
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a9dc740e-e12f-4fdd-8f2b-61a471731a14
    assert (
        actual_nt == b"\x67\xc4\x30\x11\xf3\x02\x98\xa2\xad\x35\xec\xe6\x4f\x16\x33\x1c"
        b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert (
        actual_lm == b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77\x96\x88\xa1\x72"
        b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
    )

    assert actual_kek == b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22\x00\x00\x00\x00\x00\x00\x00\x00"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x74\x52\xca\x55\xc2\x25\xa1\xca\x04\xb4\x8f\xae\x32\xcf\x56\xfc"


def test_compute_response_v1_no_session_security_lm_key():
    flags = TEST_NTLMV1_FLAGS | NegotiateFlags.lm_key
    actual_nt, actual_lm, actual_kek = crypto.compute_response_v1(
        flags,
        crypto.ntowfv1(TEST_PASSWD),
        crypto.lmowfv1(TEST_PASSWD),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
        no_lm_response=False,
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a9dc740e-e12f-4fdd-8f2b-61a471731a14
    assert (
        actual_nt == b"\x67\xc4\x30\x11\xf3\x02\x98\xa2\xad\x35\xec\xe6\x4f\x16\x33\x1c"
        b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert (
        actual_lm == b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77\x96\x88\xa1\x72"
        b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
    )
    assert actual_kek == b"\xb0\x9e\x37\x9f\x7f\xbe\xcb\x1e\xaf\x0a\xfd\xcb\x03\x83\xc8\xa0"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x4c\xd7\xbb\x57\xd6\x97\xef\x9b\x54\x9f\x02\xb8\xf9\xb3\x78\x64"


def test_compute_response_v1_session_security():
    actual_nt, actual_lm, actual_kek = crypto.compute_response_v1(
        TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS,
        crypto.ntowfv1(TEST_PASSWD),
        crypto.lmowfv1(TEST_PASSWD),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/becc1601-9c97-4553-aef7-7053d3db5883
    assert (
        actual_nt == b"\x75\x37\xf8\x03\xae\x36\x71\x28\xca\x45\x82\x04\xbd\xe7\xca\xf8"
        b"\x1e\x97\xed\x26\x83\x26\x72\x32"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/63725b2b-21fc-4977-9b56-2b3e65f7be76
    assert actual_lm == TEST_CLIENT_CHALLENGE + b"\x00" * 16

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/321bb3da-c27a-4a5d-91f9-4f23705e4029
    assert actual_kek == b"\xeb\x93\x42\x9a\x8b\xd9\x52\xf8\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc"


def test_ntowfv2():
    actual = crypto.ntowfv2(TEST_USER, crypto.ntowfv1(TEST_PASSWD), TEST_USER_DOM)

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
    assert actual == b"\x0c\x86\x8a\x40\x3b\xfd\x7a\x93\xa3\x00\x1e\xf2\x2e\xf0\x2e\x3f"


def test_compute_response_v2():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/946f54bd-76b5-4b18-ace8-6e8c992d5847
    time = FileTime.unpack(TEST_TIME)
    av_pairs = TargetInfo.unpack(
        b"\x02\x00\x0c\x00\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        b"\x01\x00\x0c\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
    )

    actual_nt, actual_lm, actual_kek = crypto.compute_response_v2(
        crypto.ntowfv2(TEST_USER, crypto.ntowfv1(TEST_PASSWD), TEST_USER_DOM),
        TEST_SERVER_CHALLENGE,
        TEST_CLIENT_CHALLENGE,
        time,
        av_pairs,
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/946f54bd-76b5-4b18-ace8-6e8c992d5847
    temp = (
        b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x02\x00\x0c\x00"
        b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x01\x00\x0c\x00"
        b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/fa2bc0f0-9efa-40d7-a165-adfccd7f6da7
    assert actual_nt == b"\x68\xcd\x0a\xb8\x51\xe5\x1c\x96\xaa\xbc\x92\x7b\xeb\xef\x6a\x1c" + temp

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7e2b35f9-fe90-49fb-8c9d-30639a899160
    assert (
        actual_lm == b"\x86\xc3\x50\x97\xac\x9c\xec\x10\x25\x54\x76\x4a\x57\xcc\xcc\x19"
        b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/54973495-20d2-49e8-9925-c399a403ed4a
    assert actual_kek == b"\x8d\xe4\x0c\xca\xdb\xc1\x4a\x82\xf1\x5c\xb0\xad\x0d\xe9\x5c\xa3"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/4a84eb20-870a-421e-984f-29a842cd6504
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\xc5\xda\xd2\x54\x4f\xc9\x79\x90\x94\xce\x1c\xe9\x0b\xc9\xd0\x3e"


@pytest.mark.parametrize(
    "flags, usage, expected",
    [
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/9cdb7bb2-17e6-409c-99cc-04590db064d4
        (NegotiateFlags.key_128, "initiate", b"\x59\xf6\x00\x97\x3c\xc4\x96\x0a\x25\x48\x0a\x7c\x19\x6e\x4c\x58"),
        (NegotiateFlags.key_128, "accept", b"\x93\x55\xf3\xa9\x57\xc1\x58\x3d\x25\xc4\xc2\xf1\x1e\x40\x39\x0e"),
        (NegotiateFlags.key_56, "initiate", b"\xa5\xf7\x25\x3c\x10\x65\xe8\xd3\xd6\x86\x42\x04\x0e\x71\xcf\xe0"),
        (NegotiateFlags.key_56, "accept", b"\x58\x3e\x2f\x98\x95\x9b\x38\x5c\xd1\x58\xf3\x73\x4b\x5f\x5d\x3f"),
        (0, "initiate", b"\x42\xf9\x64\xa4\x71\x09\x1a\x02\xff\x4a\x77\x45\x53\x66\xe4\xe5"),
        (0, "accept", b"\xc5\xd3\x85\x3b\x40\x6b\x7c\x12\x41\xc5\x95\xf0\xce\x07\x50\xe2"),
    ],
    ids=[
        "initiate-128",
        "accept-128",
        "initiate-56",
        "accept-56",
        "initiate-40",
        "accept-40",
    ],
)
def test_seal_key_ess(flags, usage, expected):
    actual = crypto.sealkey(NegotiateFlags.extended_session_security | flags, TEST_RANDOM_SESSION_KEY, usage)

    assert actual == expected


@pytest.mark.parametrize(
    "flags, expected",
    [
        (NegotiateFlags.lm_key | NegotiateFlags.key_56, b"\x55\x55\x55\x55\x55\x55\x55\xa0"),
        (NegotiateFlags.datagram | NegotiateFlags.key_56, b"\x55\x55\x55\x55\x55\x55\x55\xa0"),
        (NegotiateFlags.lm_key, b"\x55\x55\x55\x55\x55\xe5\x38\xb0"),
        (NegotiateFlags.datagram, b"\x55\x55\x55\x55\x55\xe5\x38\xb0"),
    ],
)
def test_seal_key_lm_key_or_datagram(flags, expected):
    actual = crypto.sealkey(flags, TEST_RANDOM_SESSION_KEY, "initiate")

    print(base64.b16encode(actual).decode("ascii"))

    assert actual == expected


def test_seal_key_no_flags():
    actual = crypto.sealkey(0, TEST_RANDOM_SESSION_KEY, "initiate")

    assert actual == TEST_RANDOM_SESSION_KEY


def test_signkey_no_ess():
    actual = crypto.signkey(0, b"\x01", "initiate")

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/524cdccb-563e-4793-92b0-7bc321fce096
    # If extended session security is not negotiated then no signing keys are available.
    assert not actual


def test_signkey_client():
    actual = crypto.signkey(NegotiateFlags.extended_session_security, TEST_RANDOM_SESSION_KEY, "initiate")

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/9cdb7bb2-17e6-409c-99cc-04590db064d4
    assert actual == b"\x47\x88\xdc\x86\x1b\x47\x82\xf3\x5d\x43\xfd\x98\xfe\x1a\x2d\x39"


def test_signkey_server():
    actual = crypto.signkey(NegotiateFlags.extended_session_security, TEST_RANDOM_SESSION_KEY, "accept")

    assert actual == b"\xd0\x4d\x6f\x10\x74\x10\x41\xd1\xd2\x46\xd6\x41\x88\xd7\xa8\xad"
