# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import datetime
import struct

import pytest

import spnego._ntlm_raw.messages as messages


class UTC10(datetime.tzinfo):
    """ Test UTC+10 timezone class. """

    def utcoffset(self, dt):
        return datetime.timedelta(hours=10)

    def tzname(self, dt):
        return "UTC+10"

    def dst(self, dt):
        return datetime.timedelta(hours=10)


def test_filetime_pack():
    filetime = messages.FileTime(1970, 1, 1, 0, 0, 0)
    actual = filetime.pack()

    assert actual == b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01"


def test_filetime_unpack():
    actual = messages.FileTime.unpack(b"\x00\x80\x3E\xD5\xDE\xB1\x9D\x01")

    assert isinstance(actual, messages.FileTime)
    assert str(actual) == '1970-01-01T00:00:00Z'
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

    assert str(filetime) == '1970-01-01T00:00:00.0000005Z'
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
    single_host = messages.SingleHost(size=4, z4=0, custom_data=b"\x01" * 8, machine_id=b"\x02" * 32)
    actual = single_host.pack()

    assert actual == b"\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01" \
                     b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" \
                     b"\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"


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


def test_version_eq():
    assert messages.Version.get_current() != messages.Version()
    assert messages.Version() == b"\x00" * 7 + b"\x0F"
    assert messages.Version() != b"\x11" * 8
    assert messages.Version() != 1
    assert messages.Version.get_current() == messages.Version.get_current()
