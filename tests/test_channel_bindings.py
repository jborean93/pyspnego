# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import sys

import spnego.channel_bindings as cb

TEST_DATA = cb.GssChannelBindings(
    cb.AddressType.inet, b"\x01\x02\x03\x04", cb.AddressType.unspecified, b"\x05\x06\x07\x08", b"caf\xC3\xA9"
)

TEST_B_DATA = (
    b"\x02\x00\x00\x00\x04\x00\x00\x00\x01\x02\x03\x04"
    b"\x00\x00\x00\x00\x04\x00\x00\x00\x05\x06\x07\x08"
    b"\x05\x00\x00\x00caf\xC3\xA9"
)


def test_channel_bindings_pack():
    actual = TEST_DATA.pack()

    assert actual == TEST_B_DATA


def test_channel_bindings_none_pack():
    actual = cb.GssChannelBindings().pack()

    assert actual == b"\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00"


def test_channel_bindings_unpack():
    actual = cb.GssChannelBindings.unpack(TEST_B_DATA)

    assert isinstance(actual, cb.GssChannelBindings)

    assert actual.initiator_addrtype == cb.AddressType.inet
    assert actual.initiator_address == b"\x01\x02\x03\x04"
    assert actual.acceptor_addrtype == cb.AddressType.unspecified
    assert actual.acceptor_address == b"\x05\x06\x07\x08"
    assert actual.application_data == b"caf\xC3\xA9"


def test_channel_bindings_str():
    actual = str(TEST_DATA)

    if sys.version_info[0] == 2:
        assert (
            actual == r"GssChannelBindings initiator_addr(AddressType.inet|'\x01\x02\x03\x04') | "
            r"acceptor_addr(AddressType.unspecified|'\x05\x06\x07\x08') | "
            r"application_data('caf\xc3\xa9')"
        )

    else:
        assert (
            actual == r"GssChannelBindings initiator_addr(AddressType.inet|b'\x01\x02\x03\x04') | "
            r"acceptor_addr(AddressType.unspecified|b'\x05\x06\x07\x08') | "
            r"application_data(b'caf\xc3\xa9')"
        )


def test_channel_bindings_repr():
    actual = repr(TEST_DATA)

    if sys.version_info[0] == 2:
        assert (
            actual == r"spnego.channel_bindings.GssChannelBindings initiator_addrtype=<AddressType.inet: 2>|"
            r"initiator_address='\x01\x02\x03\x04'|"
            r"acceptor_addrtype=<AddressType.unspecified: 0>|"
            r"acceptor_address='\x05\x06\x07\x08'|"
            r"application_data='caf\xc3\xa9'"
        )
    else:
        assert (
            actual == r"spnego.channel_bindings.GssChannelBindings initiator_addrtype=<AddressType.inet: 2>|"
            r"initiator_address=b'\x01\x02\x03\x04'|"
            r"acceptor_addrtype=<AddressType.unspecified: 0>|"
            r"acceptor_address=b'\x05\x06\x07\x08'|"
            r"application_data=b'caf\xc3\xa9'"
        )


def test_channel_bindings_eq():
    assert TEST_DATA == cb.GssChannelBindings.unpack(TEST_B_DATA)

    other = cb.GssChannelBindings.unpack(TEST_B_DATA)
    assert TEST_DATA == other

    assert TEST_DATA != 1

    other.acceptor_address = b"new"
    assert TEST_DATA != other
