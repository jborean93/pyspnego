# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import spnego._ntlm_raw.messages as messages


def test_target_info_pack():
    target_info = messages.TargetInfo()
    target_info[messages.AvId.timestamp] = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    target_info[messages.AvId.single_host] = b"\x00" * 48
    target_info[messages.AvId.dns_computer_name] = u"caf\u00e9-host"
    target_info[messages.AvId.eol] = b""
    target_info[messages.AvId.channel_bindings] = b"\xFF" * 16
    target_info[messages.AvId.flags] = messages.AvFlags.constrained

    actual = target_info.pack()

    assert actual == b"\x07\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"\x08\x00\x30\x00" \
                     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     b"\x03\x00\x12\x00" \
                     b"\x63\x00\x61\x00\x66\x00\xE9\x00\x2D\x00\x68\x00\x6F\x00\x73\x00" \
                     b"\x74\x00" \
                     b"\x0A\x00\x10\x00" \
                     b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
                     b"\x06\x00\x04\x00" \
                     b"\x01\x00\x00\x00" \
                     b"\x00\x00\x00\x00"


def test_target_info_unpack():
    actual = messages.TargetInfo.unpack(b"\x07\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
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
                                        b"\x00\x00\x00\x00")

    assert isinstance(actual, messages.TargetInfo)
    assert len(actual) == 6
    assert actual[messages.AvId.timestamp] == messages.FileTime.unpack(b"\x00" * 8)
    assert actual[messages.AvId.single_host] == messages.SingleHost.unpack(b"\x00" * 48)
    assert actual[messages.AvId.dns_computer_name] == u"caf\u00e9-host"
    assert actual[messages.AvId.channel_bindings] == b"\xFF" * 16
    assert actual[messages.AvId.flags] == messages.AvFlags.constrained
    assert actual[messages.AvId.eol] == b""


def test_single_host_pack():
    single_host = messages.SingleHost(4, 0, b"\x01" * 8, b"\x02" * 32)
    actual = single_host.pack()

    assert actual == b"\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01" \
                     b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" \
                     b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"


def test_single_host_unpack():
    actual = messages.SingleHost.unpack(b"\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
                                        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
                                        b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02")

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
    version = messages.Version(major=1, minor=1, build=1)
    actual = version.pack()

    assert actual == b"\x01\x01\x01\x00\x00\x00\x00\x0F"


def test_version_unpack():
    actual = messages.Version.unpack(b"\x01\x01\x01\x00\x00\x00\x00\x0F")

    assert isinstance(actual, messages.Version)
    assert str(actual) == "1.1.1.15"
    assert actual.major == 1
    assert actual.minor == 1
    assert actual.build == 1
    assert actual.revision == 15


def test_version_get_current():
    actual = messages.Version.get_current()

    assert isinstance(actual, messages.Version)
    assert len(actual.pack()) == 8


def test_version_eq():
    assert messages.Version.get_current() != messages.Version(0, 0, 0)
    assert messages.Version(0, 0, 0) == b"\x00" * 7 + b"\x0F"
    assert messages.Version(0, 0, 0) != b"\x11" * 8
    assert messages.Version(0, 0, 0) != 1
    assert messages.Version.get_current() == messages.Version.get_current()
