# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import struct

import pytest

import spnego._ntlm_raw.messages as messages

from .._ntlm_raw import (
    TEST_NTLMV1_FLAGS,
    TEST_NTLMV2_FLAGS,
    TEST_SERVER_CHALLENGE,
    TEST_SERVER_NAME,
    TEST_USER,
    TEST_USER_DOM,
    TEST_WORKSTATION_NAME,
)


class UTC10(datetime.tzinfo):
    """Test UTC+10 timezone class."""

    def utcoffset(self, dt):
        return datetime.timedelta(hours=10)

    def tzname(self, dt):
        return "UTC+10"

    def dst(self, dt):
        return datetime.timedelta(hours=10)


def test_negotiate_flags_native_labels():
    actual = messages.NegotiateFlags.native_labels()

    assert isinstance(actual, dict)
    assert actual[messages.NegotiateFlags.key_56] == "NTLMSSP_NEGOTIATE_56"


def test_av_id_native_labels():
    actual = messages.AvId.native_labels()

    assert isinstance(actual, dict)
    assert actual[messages.AvId.channel_bindings] == "MSV_AV_CHANNEL_BINDINGS"


def test_av_flags_native_labels():
    actual = messages.AvFlags.native_labels()

    assert isinstance(actual, dict)
    assert actual[messages.AvFlags.mic] == "MIC_PROVIDED"


def test_message_type_native_labels():
    actual = messages.MessageType.native_labels()

    assert isinstance(actual, dict)
    assert actual[messages.MessageType.challenge] == "CHALLENGE_MESSAGE"


def test_negotiate_pack_defaults():
    negotiate = messages.Negotiate()

    assert negotiate.flags == 0
    assert negotiate.domain_name is None
    assert negotiate.workstation is None
    assert negotiate.version is None

    actual = negotiate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
    )

    negotiate.flags = 1

    actual = negotiate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
    )


def test_negotiate_pack_with_domain():
    negotiate = messages.Negotiate(domain_name="café", workstation="café")

    assert (
        negotiate.flags
        == messages.NegotiateFlags.oem_workstation_supplied | messages.NegotiateFlags.oem_domain_name_supplied
    )
    assert negotiate.domain_name == "café"
    assert negotiate.workstation == "café"
    assert negotiate.version is None

    actual = negotiate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x20\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x24\x00\x00\x00"
        b"\x63\x61\x66\xE9"
        b"\x63\x61\x66\xE9"
    )


def test_negotiate_pack_with_all_fields():
    negotiate = messages.Negotiate(domain_name="café", workstation="café", version=messages.Version(1, 1, 1))

    assert (
        negotiate.flags
        == messages.NegotiateFlags.oem_workstation_supplied
        | messages.NegotiateFlags.oem_domain_name_supplied
        | messages.NegotiateFlags.version
    )
    assert negotiate.domain_name == "café"
    assert negotiate.workstation == "café"
    assert negotiate.version == messages.Version(1, 1, 1)

    actual = negotiate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x02"
        b"\x04\x00"
        b"\x04\x00"
        b"\x28\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x2C\x00\x00\x00"
        b"\x01\x01\x01\x00\x00\x00\x00\x0F"
        b"\x63\x61\x66\xE9"
        b"\x63\x61\x66\xE9"
    )


def test_negotiate_pack_encoding():
    negotiate = messages.Negotiate(domain_name="café", workstation="café", encoding="utf-8")

    assert (
        negotiate.flags
        == messages.NegotiateFlags.oem_workstation_supplied | messages.NegotiateFlags.oem_domain_name_supplied
    )
    assert negotiate.domain_name == "café"
    assert negotiate.workstation == "café"
    assert negotiate.version is None

    actual = negotiate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x00"
        b"\x05\x00"
        b"\x05\x00"
        b"\x20\x00\x00\x00"
        b"\x05\x00"
        b"\x05\x00"
        b"\x25\x00\x00\x00"
        b"\x63\x61\x66\xC3\xA9"
        b"\x63\x61\x66\xC3\xA9"
    )


def test_negotiate_unpack():
    actual = messages.Negotiate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x20\x00\x00\x00"
    )

    assert actual.flags == 0
    assert actual.domain_name is None
    assert actual.workstation is None
    assert actual.version is None


def test_negotiate_unpack_with_domain():
    actual = messages.Negotiate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x20\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x24\x00\x00\x00"
        b"\x63\x61\x66\xE9"
        b"\x63\x61\x66\xE9"
    )

    assert (
        actual.flags
        == messages.NegotiateFlags.oem_workstation_supplied | messages.NegotiateFlags.oem_domain_name_supplied
    )
    assert actual.domain_name == "café"
    assert actual.workstation == "café"
    assert actual.version is None


def test_negotiate_unpack_with_all_fields():
    actual = messages.Negotiate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x02"
        b"\x04\x00"
        b"\x04\x00"
        b"\x28\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x2C\x00\x00\x00"
        b"\x01\x01\x01\x00\x00\x00\x00\x0F"
        b"\x63\x61\x66\xE9"
        b"\x63\x61\x66\xE9"
    )

    assert (
        actual.flags
        == messages.NegotiateFlags.oem_workstation_supplied
        | messages.NegotiateFlags.oem_domain_name_supplied
        | messages.NegotiateFlags.version
    )

    assert actual.domain_name == "café"
    assert actual.workstation == "café"
    assert actual.version == messages.Version(1, 1, 1)


def test_negotiate_unpack_encoding():
    actual = messages.Negotiate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x00"
        b"\x05\x00"
        b"\x05\x00"
        b"\x20\x00\x00\x00"
        b"\x05\x00"
        b"\x05\x00"
        b"\x25\x00\x00\x00"
        b"\x63\x61\x66\xC3\xA9"
        b"\x63\x61\x66\xC3\xA9",
        encoding="utf-8",
    )

    assert (
        actual.flags
        == messages.NegotiateFlags.oem_workstation_supplied | messages.NegotiateFlags.oem_domain_name_supplied
    )
    assert actual.domain_name == "café"
    assert actual.workstation == "café"
    assert actual.version is None


def test_negotiate_unpack_invalid_encoding():
    # While the cars are invalid UTF-8 chars we don't want that to raise an exception for the Negotiate msg.
    actual = messages.Negotiate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x30\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x20\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x24\x00\x00\x00"
        b"\x63\x61\x66\xE9"
        b"\x63\x61\x66\xE9",
        encoding="utf-8",
    )

    assert (
        actual.flags
        == messages.NegotiateFlags.oem_workstation_supplied | messages.NegotiateFlags.oem_domain_name_supplied
    )
    assert actual.domain_name == "caf�"
    assert actual.workstation == "caf�"
    assert actual.version is None


def test_negotiate_invalid_size():
    with pytest.raises(ValueError, match="Invalid NTLM Negotiate raw byte length"):
        messages.Negotiate.unpack(b"NTLMSSP\x00\x01\x00\x00\x00")


def test_negotiate_unpack_invalid_msg():
    with pytest.raises(ValueError, match="Input message was not a NTLM Negotiate message"):
        messages.Negotiate.unpack(
            b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
            b"\x02\x00\x00\x00"
            b"\x0C\x00"
            b"\x0C\x00"
            b"\x38\x00\x00\x00"
            b"\x33\x82\x02\xE2"
            b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x06\x00\x70\x17\x00\x00\x00\x0F"
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        )


def test_challenge_pack():
    challenge = messages.Challenge()

    assert challenge.flags == 0
    assert challenge.server_challenge == b"\x00" * 8
    assert challenge.target_info is None
    assert challenge.target_name is None
    assert challenge.version is None

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x30\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x30\x00\x00\x00"
    )


def test_challenge_pack_target_name():
    challenge = messages.Challenge(
        flags=messages.NegotiateFlags.unicode, server_challenge=b"\x11" * 8, target_name="café"
    )

    assert challenge.flags == messages.NegotiateFlags.unicode | messages.NegotiateFlags.request_target
    assert challenge.server_challenge == b"\x11" * 8
    assert challenge.target_name == "café"

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x30\x00\x00\x00"
        b"\x05\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x38\x00\x00\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00"
    )


def test_challenge_pack_target_name_oem():
    challenge = messages.Challenge(flags=messages.NegotiateFlags.oem, server_challenge=b"\x11" * 8, target_name="café")

    assert challenge.flags == messages.NegotiateFlags.oem | messages.NegotiateFlags.request_target
    assert challenge.server_challenge == b"\x11" * 8
    assert challenge.target_name == "café"

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x30\x00\x00\x00"
        b"\x06\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x34\x00\x00\x00"
        b"\x63\x61\x66\xE9"
    )


def test_challenge_pack_target_info():
    ti = messages.TargetInfo()
    ti[messages.AvId.dns_computer_name] = "café"
    # Even with the OEM encoding flag, the target info should still be utf-16-le.
    challenge = messages.Challenge(flags=messages.NegotiateFlags.oem, server_challenge=b"\x11" * 8, target_info=ti)

    assert challenge.flags == messages.NegotiateFlags.oem | messages.NegotiateFlags.target_info
    assert challenge.server_challenge == b"\x11" * 8
    assert challenge.target_name is None
    assert challenge.target_info is not None
    assert len(challenge.target_info) == 2
    assert challenge.target_info[messages.AvId.dns_computer_name] == "café"
    assert challenge.target_info[messages.AvId.eol] == b""
    assert challenge.version is None

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x30\x00\x00\x00"
        b"\x02\x00\x80\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x30\x00\x00\x00"
        b"\x03\x00\x08\x00\x63\x00\x61\x00\x66\x00\xE9\x00"
        b"\x00\x00\x00\x00"
    )


def test_challenge_pack_all_fields():
    ti = messages.TargetInfo()
    ti[messages.AvId.dns_computer_name] = "café"
    challenge = messages.Challenge(
        flags=messages.NegotiateFlags.unicode,
        server_challenge=b"\x11" * 8,
        target_name="café",
        target_info=ti,
        version=messages.Version(2, 2, 2),
    )

    assert (
        challenge.flags
        == messages.NegotiateFlags.target_info
        | messages.NegotiateFlags.request_target
        | messages.NegotiateFlags.version
        | messages.NegotiateFlags.unicode
    )
    assert challenge.server_challenge == b"\x11" * 8
    assert challenge.target_name == "café"
    assert challenge.target_info is not None
    assert len(challenge.target_info) == 2
    assert challenge.target_info[messages.AvId.dns_computer_name] == "café"
    assert challenge.target_info[messages.AvId.eol] == b""
    assert challenge.version == messages.Version(2, 2, 2)

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x38\x00\x00\x00"
        b"\x05\x00\x80\x02"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x40\x00\x00\x00"
        b"\x02\x02\x02\x00\x00\x00\x00\x0F"
        b"\x63\x00\x61\x00\x66\x00\xE9"
        b"\x00\x03\x00\x08\x00\x63\x00\x61\x00\x66\x00\xE9\x00"
        b"\x00\x00\x00\x00"
    )


def test_challenge_set_fields():
    challenge = messages.Challenge()

    challenge.flags = 10
    challenge.server_challenge = b"\xFF" * 8

    actual = challenge.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x30\x00\x00\x00"
        b"\x0A\x00\x00\x00"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x30\x00\x00\x00"
    )


def test_challenge_invalid_server_challenge_length():
    expected = "NTLM Challenge ServerChallenge must be 8 bytes long"
    with pytest.raises(ValueError, match=expected):
        messages.Challenge(server_challenge=b"\x00")

    challenge = messages.Challenge()
    with pytest.raises(ValueError, match=expected):
        challenge.server_challenge = b"\x08"


def test_challenge_invalid_size():
    with pytest.raises(ValueError, match="Invalid NTLM Challenge raw byte length"):
        messages.Challenge.unpack(b"NTLMSSP\x00\x02\x00\x00\x00")


def test_challenge_unpack_ntlmv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/ee78f3ad-ae29-4de1-96a0-fe46e64b6e31
    actual = messages.Challenge.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x38\x00\x00\x00"
        b"\x33\x82\x02\xE2"
        b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x06\x00\x70\x17\x00\x00\x00\x0F"
        b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
    )

    assert actual.target_name == TEST_SERVER_NAME
    assert actual.flags == TEST_NTLMV1_FLAGS
    assert actual.server_challenge == TEST_SERVER_CHALLENGE
    assert actual.target_info is None
    assert actual.version == messages.Version(6, 0, 6000)


def test_challenge_unpack_ntlmv2():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bc612491-fb0b-4829-91bc-7c6b95ff67fe
    actual = messages.Challenge.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x38\x00\x00\x00"
        b"\x33\x82\x8A\xE2"
        b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x24\x00"
        b"\x24\x00"
        b"\x44\x00\x00\x00"
        b"\x06\x00\x70\x17\x00\x00\x00\x0F"
        b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
    )

    assert actual.target_name == TEST_SERVER_NAME
    assert actual.flags == TEST_NTLMV2_FLAGS
    assert actual.server_challenge == TEST_SERVER_CHALLENGE
    assert actual.target_info is not None
    assert len(actual.target_info) == 3
    assert actual.target_info[messages.AvId.nb_domain_name] == TEST_USER_DOM
    assert actual.target_info[messages.AvId.nb_computer_name] == TEST_SERVER_NAME
    assert actual.target_info[messages.AvId.eol] == b""
    assert actual.version == messages.Version(6, 0, 6000)


def test_challenge_unpack_encoding():
    actual = messages.Challenge.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x02\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x30\x00\x00\x00"
        b"\x06\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x34\x00\x00\x00"
        b"\x63\x61\x66\xE9"
    )

    assert actual.target_name == "café"
    assert actual.flags == messages.NegotiateFlags.oem | messages.NegotiateFlags.request_target
    assert actual.server_challenge == b"\x11" * 8
    assert actual.target_info is None
    assert actual.version is None


def test_challenge_unpack_invalid_msg():
    with pytest.raises(ValueError, match="Input message was not a NTLM Challenge message"):
        messages.Challenge.unpack(
            b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x20\x00\x00\x00"
        )


def test_authenticate_pack():
    authenticate = messages.Authenticate()

    assert authenticate.lm_challenge_response is None
    assert authenticate.nt_challenge_response is None
    assert authenticate.domain_name is None
    assert authenticate.user_name is None
    assert authenticate.workstation is None
    assert authenticate.encrypted_random_session_key is None
    assert authenticate.flags == 0
    assert authenticate.version is None
    assert authenticate.mic == b"\x00" * 16

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )


def test_authenticate_pack_domain_version():
    authenticate = messages.Authenticate(
        flags=messages.NegotiateFlags.unicode, domain_name="café", version=messages.Version(1, 1, 1)
    )

    assert authenticate.lm_challenge_response is None
    assert authenticate.nt_challenge_response is None
    assert authenticate.domain_name == "café"
    assert authenticate.user_name is None
    assert authenticate.workstation is None
    assert authenticate.encrypted_random_session_key is None
    assert authenticate.flags == messages.NegotiateFlags.version | messages.NegotiateFlags.unicode
    assert authenticate.mic == b"\x00" * 16
    assert authenticate.version == messages.Version(1, 1, 1)

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x58\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x58\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x58\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x60\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x60\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x60\x00\x00\x00"
        b"\x01\x00\x00\x02"
        b"\x01\x01\x01\x00\x00\x00\x00\x0F"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00"
    )


def test_authenticate_pack_oem_encoding():
    authenticate = messages.Authenticate(
        flags=messages.NegotiateFlags.oem, domain_name="café", version=messages.Version(1, 1, 1)
    )

    assert authenticate.lm_challenge_response is None
    assert authenticate.nt_challenge_response is None
    assert authenticate.domain_name == "café"
    assert authenticate.user_name is None
    assert authenticate.workstation is None
    assert authenticate.encrypted_random_session_key is None
    assert authenticate.flags == messages.NegotiateFlags.version | messages.NegotiateFlags.oem
    assert authenticate.mic == b"\x00" * 16
    assert authenticate.version == messages.Version(1, 1, 1)

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x58\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x58\x00\x00\x00"
        b"\x04\x00"
        b"\x04\x00"
        b"\x58\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x5C\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x5C\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x5C\x00\x00\x00"
        b"\x02\x00\x00\x02"
        b"\x01\x01\x01\x00\x00\x00\x00\x0F"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x63\x61\x66\xE9"
    )


def test_authenticate_set_flags():
    authenticate = messages.Authenticate()
    authenticate.flags = 1

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )


def test_authenticate_set_mic():
    authenticate = messages.Authenticate()
    authenticate.mic = b"\xFF" * 16

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    )


def test_authenticate_set_encrypted_session_key():
    authenticate = messages.Authenticate(encrypted_session_key=b"\x01")

    actual = authenticate.pack()

    assert (
        actual == b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x01\x00"
        b"\x01\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00\x00\x40"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x01"
    )


def test_authenticate_invalid_mic_length():
    expected = "NTLM Authenticate MIC must be 16 bytes long"

    with pytest.raises(ValueError, match=expected):
        messages.Authenticate(mic=b"\x00")

    authenticate = messages.Authenticate()
    with pytest.raises(ValueError, match=expected):
        authenticate.mic = b"\x00"


def test_authenticate_set_mic_not_present():
    authenticate = messages.Authenticate.unpack(b"NTLMSSP\x00\x03\x00\x00\x00" + (b"\x00" * 52))

    assert authenticate.mic is None

    with pytest.raises(ValueError, match="Cannot set MIC on an Authenticate message with no MIC present"):
        authenticate.mic = b"\x11" * 16


def test_authenticate_unpack_empty():
    actual = messages.Authenticate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x50\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    assert actual.lm_challenge_response is None
    assert actual.nt_challenge_response is None
    assert actual.domain_name is None
    assert actual.user_name is None
    assert actual.workstation is None
    assert actual.encrypted_random_session_key is None
    assert actual.flags == 0
    assert actual.version is None
    assert actual.mic == b"\x00" * 16


def test_authenticate_unpack_ntlmv1():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/ee78f3ad-ae29-4de1-96a0-fe46e64b6e31
    actual = messages.Authenticate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x6C\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x84\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x48\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x54\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x5C\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x9C\x00\x00\x00"
        b"\x35\x82\x80\xE2"
        b"\x05\x01\x28\x0A\x00\x00\x00\x0F"
        b"\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x55\x00\x73\x00\x65\x00\x72\x00"
        b"\x43\x00\x4F\x00\x4D\x00\x50\x00\x55\x00\x54\x00\x45\x00\x52\x00"
        b"\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D\xAF\xE2\xDF\x77\x96\x88\xA1\x72"
        b"\xDE\xF1\x1C\x7D\x5C\xCD\xEF\x13"
        b"\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
        b"\x51\x88\x22\xB1\xB3\xF3\x50\xC8\x95\x86\x82\xEC\xBB\x3E\x3C\xB7"
    )

    assert (
        actual.lm_challenge_response == b"\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D"
        b"\xAF\xE2\xDF\x77\x96\x88\xA1\x72"
        b"\xDE\xF1\x1C\x7D\x5C\xCD\xEF\x13"
    )
    assert (
        actual.nt_challenge_response == b"\x67\xC4\x30\x11\xF3\x02\x98\xA2"
        b"\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
    )
    assert actual.domain_name == TEST_USER_DOM
    assert actual.user_name == TEST_USER
    assert actual.workstation == TEST_WORKSTATION_NAME
    assert (
        actual.encrypted_random_session_key == b"\x51\x88\x22\xB1\xB3\xF3\x50\xC8" b"\x95\x86\x82\xEC\xBB\x3E\x3C\xB7"
    )
    assert actual.flags == 3800072757
    assert actual.mic is None
    assert actual.version == messages.Version(5, 1, 2600)


def test_authenticate_unpack_ntlmv2():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bc612491-fb0b-4829-91bc-7c6b95ff67fe
    actual = messages.Authenticate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x6C\x00\x00\x00"
        b"\x54\x00"
        b"\x54\x00"
        b"\x84\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x48\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x54\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x5C\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\xD8\x00\x00\x00"
        b"\x35\x82\x88\xE2"
        b"\x05\x01\x28\x0A\x00\x00\x00\x0F"
        b"\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x55\x00\x73\x00\x65\x00\x72\x00"
        b"\x43\x00\x4F\x00\x4D\x00\x50\x00\x55\x00\x54\x00\x45\x00\x52\x00"
        b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C"
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x00\x00\x00\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xC5\xDA\xD2\x54\x4F\xC9\x79\x90\x94\xCE\x1C\xE9\x0B\xC9\xD0\x3E"
    )

    assert (
        actual.lm_challenge_response == b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10"
        b"\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    )
    assert (
        actual.nt_challenge_response == b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96"
        b"\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C"
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x00\x00\x00\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    assert actual.domain_name == TEST_USER_DOM
    assert actual.user_name == TEST_USER
    assert actual.workstation == TEST_WORKSTATION_NAME
    assert (
        actual.encrypted_random_session_key == b"\xC5\xDA\xD2\x54\x4F\xC9\x79\x90" b"\x94\xCE\x1C\xE9\x0B\xC9\xD0\x3E"
    )
    assert actual.flags == 3800597045
    assert actual.mic is None
    assert actual.version == messages.Version(5, 1, 2600)


def test_authenticate_unpack_mic_no_version():
    actual = messages.Authenticate.unpack(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x50\x00\x00\x00"
        b"\x54\x00"
        b"\x54\x00"
        b"\x68\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\xBC\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\xC4\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\xCC\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\xD4\x00\x00\x00"
        b"\x31\x82\x8A\xE2"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10"
        b"\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96"
        b"\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C"
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x00\x00\x00\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00"
        b"\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00"
        b"\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00"
    )

    assert (
        actual.lm_challenge_response == b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10"
        b"\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
    )
    assert (
        actual.nt_challenge_response == b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96"
        b"\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C"
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x00\x00\x00\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    assert actual.domain_name == "café"
    assert actual.user_name == "café"
    assert actual.workstation == "café"
    assert actual.encrypted_random_session_key is None
    assert actual.flags == 3800728113
    assert actual.mic == b"\x11" * 16
    assert actual.version is None


def test_authenticate_invalid_size():
    with pytest.raises(ValueError, match="Invalid NTLM Authenticate raw byte length"):
        messages.Authenticate.unpack(b"NTLMSSP\x00\x03\x00\x00\x00")


def test_authenticate_unpack_invalid_msg():
    with pytest.raises(ValueError, match="Input message was not a NTLM Authenticate message"):
        messages.Authenticate.unpack(
            b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00"
            b"\x00\x00"
            b"\x20\x00\x00\x00"
        )


def test_filetime_pack():
    filetime = messages.FileTime(1970, 1, 1, 0, 0, 0)
    actual = filetime.pack()

    assert actual == b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"


def test_filetime_unpack():
    actual = messages.FileTime.unpack(b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01")

    assert isinstance(actual, messages.FileTime)
    assert str(actual) == "1970-01-01T00:00:00Z"
    assert actual.year == 1970
    assert actual.month == 1
    assert actual.day == 1
    assert actual.hour == 0
    assert actual.minute == 0
    assert actual.second == 0
    assert actual.microsecond == 0
    assert actual.nanosecond == 0


def test_filetime_from_datetime_nanoseconds():
    filetime = messages.FileTime.from_datetime(datetime.datetime(1970, 1, 1, 0, 0, 0), ns=500)
    actual = filetime.pack()

    assert str(filetime) == "1970-01-01T00:00:00.0000005Z"
    assert filetime.nanosecond == 500

    assert actual == b"\x05\x80\x3E\xD5\xDE\xB1\x9D\x01"


def test_filetime_now():
    current = messages.FileTime.from_datetime(datetime.datetime.now())
    now = messages.FileTime.now()

    current_int = struct.unpack("<Q", current.pack())[0]
    now_int = struct.unpack("<Q", now.pack())[0]

    assert now_int >= current_int


def test_filetime_with_timezone():
    filetime = messages.FileTime(1970, 1, 1, 10, 0, 0, tzinfo=UTC10())

    assert str(filetime) == "1970-01-01T10:00:00+10:00"

    actual = filetime.pack()  # Should be the same as EPOCH in UTC as FILETIME.
    assert actual == b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"


def test_nt_challenge_pack():
    challenge = messages.NTClientChallengeV2()
    assert challenge.resp_type == 1
    assert challenge.hi_resp_type == 1
    assert isinstance(challenge.time_stamp, messages.FileTime)
    assert challenge.challenge_from_client == b"\x00" * 8
    assert len(challenge.av_pairs) == 1

    challenge.time_stamp = messages.FileTime.unpack(b"\x00\x00\x00\x00\x00\x00\x00\x00")

    actual = challenge.pack()

    assert (
        actual == b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )


def test_nt_challenge_create():
    ft = messages.FileTime.unpack(b"\x11" * 8)
    av = messages.TargetInfo()
    av[messages.AvId.dns_domain_name] = "test"

    actual = messages.NTClientChallengeV2(time_stamp=ft, client_challenge=b"\x11" * 8, av_pairs=av)

    assert actual.resp_type == 1
    assert actual.hi_resp_type == 1
    assert actual.time_stamp.pack() == b"\x11" * 8
    assert actual.challenge_from_client == b"\x11" * 8
    assert len(actual.av_pairs) == 2
    assert actual.av_pairs[messages.AvId.dns_domain_name] == "test"

    assert (
        actual.pack() == b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x11\x11\x11\x11\x11\x11\x11\x11"
        b"\x00\x00\x00\x00"
        b"\x04\x00\x08\x00"
        b"\x74\x00\x65\x00\x73\x00\x74\x00"
        b"\x00\x00\x00\x00"
    )


def test_nt_challenge_unpack():
    challenge = messages.NTClientChallengeV2.unpack(
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    assert challenge.resp_type == 1
    assert challenge.hi_resp_type == 1
    assert isinstance(challenge.time_stamp, messages.FileTime)
    assert challenge.time_stamp.pack() == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert challenge.challenge_from_client == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert isinstance(challenge.av_pairs, messages.TargetInfo)
    assert challenge.av_pairs.pack() == b"\x00\x00\x00\x00"


def test_nt_challenge_unpack_invalid_size():
    with pytest.raises(ValueError, match="Invalid NTClientChallengeV2 raw byte length"):
        messages.NTClientChallengeV2.unpack(b"\x00")


def test_nt_challenge_resp_type():
    challenge = messages.NTClientChallengeV2()
    assert challenge.resp_type == 1
    challenge.resp_type = 2
    assert challenge.resp_type == 2
    assert challenge.pack()[:1] == b"\x02"


def test_nt_challenge_hi_resp_type():
    challenge = messages.NTClientChallengeV2()
    assert challenge.hi_resp_type == 1
    challenge.hi_resp_type = 2
    assert challenge.hi_resp_type == 2
    assert challenge.pack()[1:2] == b"\x02"


def test_nt_challenge_client_challenge():
    challenge = messages.NTClientChallengeV2()
    assert challenge.challenge_from_client == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    challenge.challenge_from_client = b"\xFF" * 8
    assert challenge.challenge_from_client == b"\xFF" * 8
    assert challenge.pack()[16:24] == b"\xFF" * 8


def test_nt_challenge_client_challenge_bad_length():
    expected = "NTClientChallengeV2 ChallengeFromClient must be 8 bytes long"

    with pytest.raises(ValueError, match=expected):
        messages.NTClientChallengeV2(client_challenge=b"\x00")

    challenge = messages.NTClientChallengeV2()
    with pytest.raises(ValueError, match=expected):
        challenge.challenge_from_client = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_target_info_pack():
    target_info = messages.TargetInfo()
    target_info[messages.AvId.timestamp] = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    target_info[messages.AvId.single_host] = b"\x00" * 48
    target_info[messages.AvId.dns_computer_name] = "caf\u00e9-host"
    target_info[messages.AvId.eol] = b""
    target_info[messages.AvId.channel_bindings] = b"\xFF" * 16
    target_info[messages.AvId.flags] = messages.AvFlags.constrained

    actual = target_info.pack()

    assert (
        actual == b"\x07\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x08\x00\x30\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x12\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00\x2D\x00\x68\x00\x6F\x00\x73\x00"
        b"\x74\x00"
        b"\x0A\x00\x10\x00"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\x06\x00\x04\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )


def test_target_info_unpack():
    actual = messages.TargetInfo.unpack(
        b"\x07\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x08\x00\x30\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x03\x00\x12\x00"
        b"\x63\x00\x61\x00\x66\x00\xE9\x00\x2D\x00\x68\x00\x6F\x00\x73\x00"
        b"\x74\x00"
        b"\x0A\x00\x10\x00"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\x06\x00\x04\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )

    assert isinstance(actual, messages.TargetInfo)
    assert len(actual) == 6
    assert actual[messages.AvId.timestamp] == messages.FileTime.unpack(b"\x00" * 8)
    assert actual[messages.AvId.single_host] == messages.SingleHost.unpack(b"\x00" * 48)
    assert actual[messages.AvId.dns_computer_name] == "caf\u00e9-host"
    assert actual[messages.AvId.channel_bindings] == b"\xFF" * 16
    assert actual[messages.AvId.flags] == messages.AvFlags.constrained
    assert actual[messages.AvId.eol] == b""


def test_single_host_pack():
    single_host = messages.SingleHost(size=4, z4=0, custom_data=b"\x01" * 8, machine_id=b"\x02" * 32)
    actual = single_host.pack()

    assert (
        actual == b"\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
    )


def test_single_host_defaults():
    actual = messages.SingleHost()

    assert actual.size == 0
    assert actual.z4 == 0
    assert actual.custom_data == b"\x00" * 8
    assert actual.machine_id == b"\x00" * 32


def test_single_host_invalid_size():
    with pytest.raises(ValueError, match="SingleHost bytes must have a length of 48"):
        messages.SingleHost.unpack(b_data=b"\x00")


def test_single_host_invalid_custom_data_size():
    single_host = messages.SingleHost()

    with pytest.raises(ValueError, match="custom_data length must be 8 bytes long"):
        single_host.custom_data = b"\x00"


def test_single_host_invalid_machine_id_size():
    single_host = messages.SingleHost()

    with pytest.raises(ValueError, match="machine_id length must be 32 bytes long"):
        single_host.machine_id = b"\x00"


def test_single_host_unpack():
    actual = messages.SingleHost.unpack(
        b"\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
    )

    assert isinstance(actual, messages.SingleHost)
    assert actual.size == 4
    assert actual.z4 == 0
    assert actual.custom_data == b"\x01" * 8
    assert actual.machine_id == b"\x02" * 32


def test_single_host_eq():
    assert messages.SingleHost.unpack(b"\x00" * 48) == b"\x00" * 48
    assert messages.SingleHost.unpack(b"\x00" * 48) != b"\x11" * 48
    assert messages.SingleHost.unpack(b"\x00" * 48) != 1
    assert messages.SingleHost.unpack(b"\x00" * 48) == messages.SingleHost.unpack(b"\x00" * 48)


def test_version_pack():
    version = messages.Version(major=1, minor=2, build=3, revision=4)
    assert version.major == 1
    assert version.minor == 2
    assert version.build == 3
    assert version.revision == 4
    assert len(version) == 8

    version.major = 1
    version.minor = 1
    version.build = 1
    version.revision = 10
    actual = version.pack()

    assert actual == b"\x01\x01\x01\x00\x00\x00\x00\x0A"


def test_version_defaults():
    version = messages.Version()

    assert version.major == 0
    assert version.minor == 0
    assert version.build == 0
    assert version.reserved == b"\x00\x00\x00"
    assert version.revision == 15
    assert len(version) == 8


def test_version_unpack():
    actual = messages.Version.unpack(b"\x01\x01\x01\x00\x00\x00\x00\x0F")

    assert isinstance(actual, messages.Version)
    assert str(actual) == "1.1.1.15"
    assert repr(actual) == "<spnego._ntlm_raw.messages.Version 1.1.1.15>"
    assert actual.major == 1
    assert actual.minor == 1
    assert actual.build == 1
    assert actual.reserved == b"\x00\x00\x00"
    assert actual.revision == 15
    assert len(actual) == 8


def test_version_unpack_incorrect_length():
    with pytest.raises(ValueError, match="Version bytes must have a length of 8"):
        messages.Version.unpack(b"\x00")


def test_version_get_current():
    actual = messages.Version.get_current()

    assert isinstance(actual, messages.Version)
    assert len(actual) == 8
    assert len(actual.pack()) == 8


@pytest.mark.parametrize(
    "version, major, minor, build",
    [
        ("0.1.0.dev1", 0, 1, 0),
        ("0.1.0b1", 0, 1, 0),
        ("0.1.10b1", 0, 1, 10),
        ("0.1.0a1", 0, 1, 0),
        ("0.1.0", 0, 1, 0),
        ("0", 0, 0, 0),
        ("1", 1, 0, 0),
        ("1.2", 1, 2, 0),
        ("1..", 1, 0, 0),
    ],
)
def test_version_get_current_formats(version, major, minor, build, monkeypatch):
    monkeypatch.setattr(messages, "pyspnego_version", version)

    actual = messages.Version.get_current()
    assert actual.major == major
    assert actual.minor == minor
    assert actual.build == build


def test_version_eq():
    assert messages.Version.get_current() != messages.Version()
    assert messages.Version() == b"\x00" * 7 + b"\x0F"
    assert messages.Version() != b"\x11" * 8
    assert messages.Version() != 1
    assert messages.Version.get_current() == messages.Version.get_current()
