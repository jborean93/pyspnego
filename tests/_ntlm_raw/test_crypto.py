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
    assert actual == b"\x26\x39\xF4\xCB"


def test_lmowfv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a724e8df-2b0a-4a36-aef4-2d2b56fd3db7
    actual = crypto.lmowfv1(TEST_PASSWD)

    assert actual == b"\xE5\x2C\xAC\x67\x41\x9A\x9A\x22\x4A\x3B\x10\x8F\x3F\xA6\xCB\x6D"


def test_lmowfv1_hash():
    lm_hash = os.urandom(16)
    nt_hash = os.urandom(16)
    ntlm_hash = to_text(b"%s:%s" % (base64.b16encode(lm_hash), base64.b16encode(nt_hash)))

    actual = crypto.lmowfv1(ntlm_hash)

    assert actual == lm_hash


def test_ntowfv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/0fb94d19-16d2-481d-9121-112defbaac0b
    actual = crypto.ntowfv1(TEST_PASSWD)

    assert actual == b"\xA4\xF4\x9C\x40\x65\x10\xBD\xCA\xB6\x82\x4E\xE7\xC3\x0F\xD8\x52"


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
        actual_nt == b"\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert actual_lm == actual_nt

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/0b344a44-7cd8-4ab5-b07c-ff2b3d8c15f4
    assert actual_kek == b"\xD8\x72\x62\xB0\xCD\xE4\xB1\xCB\x74\x99\xBE\xCC\xCD\xF1\x07\x84"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x51\x88\x22\xB1\xB3\xF3\x50\xC8\x95\x86\x82\xEC\xBB\x3E\x3C\xB7"


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
        actual_nt == b"\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert (
        actual_lm == b"\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D\xAF\xE2\xDF\x77\x96\x88\xA1\x72"
        b"\xDE\xF1\x1C\x7D\x5C\xCD\xEF\x13"
    )

    assert actual_kek == b"\xE5\x2C\xAC\x67\x41\x9A\x9A\x22\x00\x00\x00\x00\x00\x00\x00\x00"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x74\x52\xCA\x55\xC2\x25\xA1\xCA\x04\xB4\x8F\xAE\x32\xCF\x56\xFC"


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
        actual_nt == b"\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/859a18d1-d7b2-4e98-a261-5b38cdf4b11d
    assert (
        actual_lm == b"\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D\xAF\xE2\xDF\x77\x96\x88\xA1\x72"
        b"\xDE\xF1\x1C\x7D\x5C\xCD\xEF\x13"
    )
    assert actual_kek == b"\xB0\x9E\x37\x9F\x7F\xBE\xCB\x1E\xAF\x0A\xFD\xCB\x03\x83\xC8\xA0"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2d7f9599-f849-4550-9579-91aeea8078b0
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\x4C\xD7\xBB\x57\xD6\x97\xEF\x9B\x54\x9F\x02\xB8\xF9\xB3\x78\x64"


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
        actual_nt == b"\x75\x37\xF8\x03\xAE\x36\x71\x28\xCA\x45\x82\x04\xBD\xE7\xCA\xF8"
        b"\x1E\x97\xED\x26\x83\x26\x72\x32"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/63725b2b-21fc-4977-9b56-2b3e65f7be76
    assert actual_lm == TEST_CLIENT_CHALLENGE + b"\x00" * 16

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/321bb3da-c27a-4a5d-91f9-4f23705e4029
    assert actual_kek == b"\xEB\x93\x42\x9A\x8B\xD9\x52\xF8\xB8\x9C\x55\xB8\x7F\x47\x5E\xDC"


def test_ntowfv2():
    actual = crypto.ntowfv2(TEST_USER, crypto.ntowfv1(TEST_PASSWD), TEST_USER_DOM)

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
    assert actual == b"\x0C\x86\x8A\x40\x3B\xFD\x7A\x93\xA3\x00\x1E\xF2\x2E\xF0\x2E\x3F"


def test_compute_response_v2():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/946f54bd-76b5-4b18-ace8-6e8c992d5847
    time = FileTime.unpack(TEST_TIME)
    av_pairs = TargetInfo.unpack(
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
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
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\x00\x00\x00\x00\x02\x00\x0C\x00"
        b"\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00\x01\x00\x0C\x00"
        b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/fa2bc0f0-9efa-40d7-a165-adfccd7f6da7
    assert actual_nt == b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C" + temp

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7e2b35f9-fe90-49fb-8c9d-30639a899160
    assert (
        actual_lm == b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    )

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/54973495-20d2-49e8-9925-c399a403ed4a
    assert actual_kek == b"\x8D\xE4\x0C\xCA\xDB\xC1\x4A\x82\xF1\x5C\xB0\xAD\x0D\xE9\x5C\xA3"

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/4a84eb20-870a-421e-984f-29a842cd6504
    actual_enc_key = crypto.rc4k(actual_kek, TEST_RANDOM_SESSION_KEY)
    assert actual_enc_key == b"\xC5\xDA\xD2\x54\x4F\xC9\x79\x90\x94\xCE\x1C\xE9\x0B\xC9\xD0\x3E"


@pytest.mark.parametrize(
    "flags, usage, expected",
    [
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/9cdb7bb2-17e6-409c-99cc-04590db064d4
        (NegotiateFlags.key_128, "initiate", b"\x59\xF6\x00\x97\x3C\xC4\x96\x0A\x25\x48\x0A\x7C\x19\x6E\x4C\x58"),
        (NegotiateFlags.key_128, "accept", b"\x93\x55\xF3\xA9\x57\xC1\x58\x3D\x25\xC4\xC2\xF1\x1E\x40\x39\x0E"),
        (NegotiateFlags.key_56, "initiate", b"\xA5\xF7\x25\x3C\x10\x65\xE8\xD3\xD6\x86\x42\x04\x0E\x71\xCF\xE0"),
        (NegotiateFlags.key_56, "accept", b"\x58\x3E\x2F\x98\x95\x9B\x38\x5C\xD1\x58\xF3\x73\x4B\x5F\x5D\x3F"),
        (0, "initiate", b"\x42\xF9\x64\xA4\x71\x09\x1A\x02\xFF\x4A\x77\x45\x53\x66\xE4\xE5"),
        (0, "accept", b"\xC5\xD3\x85\x3B\x40\x6B\x7C\x12\x41\xC5\x95\xF0\xCE\x07\x50\xE2"),
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
        (NegotiateFlags.lm_key | NegotiateFlags.key_56, b"\x55\x55\x55\x55\x55\x55\x55\xA0"),
        (NegotiateFlags.datagram | NegotiateFlags.key_56, b"\x55\x55\x55\x55\x55\x55\x55\xA0"),
        (NegotiateFlags.lm_key, b"\x55\x55\x55\x55\x55\xE5\x38\xB0"),
        (NegotiateFlags.datagram, b"\x55\x55\x55\x55\x55\xE5\x38\xB0"),
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
    assert actual == b"\x47\x88\xDC\x86\x1B\x47\x82\xF3\x5D\x43\xFD\x98\xFE\x1A\x2D\x39"


def test_signkey_server():
    actual = crypto.signkey(NegotiateFlags.extended_session_security, TEST_RANDOM_SESSION_KEY, "accept")

    assert actual == b"\xD0\x4D\x6F\x10\x74\x10\x41\xD1\xD2\x46\xD6\x41\x88\xD7\xA8\xAD"
