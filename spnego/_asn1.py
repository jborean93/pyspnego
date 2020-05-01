# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import struct


class TagClass:
    universal = 0
    application = 1
    context_specific = 2
    private = 3


class TypeTagNumber:
    boolean = 1
    integer = 2
    bit_string = 3
    octet_string = 4
    null = 5
    object_identifier = 6
    object_descriptor = 7
    external = 8
    real = 9
    enumerated = 10
    embedded_pdv = 11
    utf8_string = 12
    relative_oid = 13
    time = 14
    reserved = 15
    sequence = 16
    sequence_of = 16
    set = 17
    set_of = 17
    numeric_string = 18
    printable_string = 19
    t61_string = 20
    videotex_string = 21
    ia5_string = 22
    utc_time = 23
    generalized_time = 24
    graphic_string = 25
    visible_string = 26
    general_string = 27
    universal_string = 28
    character_string = 29
    bmp_string = 30
    date = 31
    time_of_day = 32
    date_time = 33
    duration = 34
    oid_iri = 35
    relative_oid_iri = 36


def pack_asn1(tag_class, constructed, tag_number, b_data):
    """
    Pack the contents into an ASN.1 structure. The structure is in the form.

    | Identifier Octet(s) | Length Octet(s) | Data Octet(s) |

    :param tag_class: The tag class of the data from 0 to 3.
    :param constructed: Whether the data is constructed or primitive.
    :param tag_number: The tag number of the content.
    :param b_data: The data to pack with the header.
    :return: The packed ASN.1 data as a byte string.
    """
    b_asn1_data = bytearray()

    # ASN.1 Identifier octet is
    #
    # |             Octet 1             |  |              Octet 2              |
    # | 8 | 7 |  6  | 5 | 4 | 3 | 2 | 1 |  |   8   | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Class | P/C | Tag Number (0-30) |  | More  | Tag number                |
    #
    # If Tag Number is >= 31 the first 5 bits are 1 and the 2nd octet is used to encode the length.
    if tag_class < 0 or tag_class > 3:
        raise ValueError("tag_class must be between 0 and 3")

    identifier_octets = tag_class << 6
    identifier_octets |= ((1 if constructed else 0) << 5)

    if tag_number < 31:
        identifier_octets |= tag_number
        b_asn1_data.append(identifier_octets)
    else:
        # Set the first 5 bits of the first octet to 1 and encode the tag number in subsequent octets.
        identifier_octets |= 31
        b_asn1_data.append(identifier_octets)
        b_asn1_data.extend(pack_asn1_octet_number(tag_number))

    # ASN.1 Length octet for DER encoding is always in the definite form. This form packs the lengths in the following
    # octet structure:
    #
    # |                       Octet 1                       |  |            Octet n            |
    # |     8     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 |
    # | Long form | Short = length, Long = num octets       |  | Big endian length for long    |
    #
    # Basically if the length < 127 it's encoded in the first octet, otherwise the first octet 7 bits indicates how
    # many subsequent octets were used to encode the length.
    length = len(b_data)
    if length < 128:
        b_asn1_data.append(length)
    else:
        length_octets = bytearray()
        while length:
            length_octets.append(length & 0b11111111)
            length >>= 8

        # Reverse the octets so the higher octets are first, add the initial length octet with the MSB set and add them
        # all to the main ASN.1 byte array.
        length_octets.reverse()
        b_asn1_data.append(len(length_octets) | 0b10000000)
        b_asn1_data.extend(length_octets)

    return bytes(b_asn1_data) + b_data


def pack_asn1_enumerated(value, tag=True):
    b_data = pack_asn1_integer(value, tag=False)
    if tag:
        b_data = pack_asn1(TagClass.universal, False, TypeTagNumber.enumerated, b_data)

    return b_data


def pack_asn1_integer(value, tag=True):
    """
    Thanks to https://github.com/andrivet/python-asn1 as I couldn't wrap my head around the negative numbers.

    :param value:
    :param tag:
    :return:
    """
    is_negative = False
    limit = 0x7f
    if value < 0:
        value = -value
        is_negative = True
        limit = 0x80

    b_int = bytearray()
    while value > limit:
        val = value & 0xff

        if is_negative:
            val = 0xff - val

        b_int.append(val)
        value >>= 8

    b_int.append(((0xff - value) if is_negative else value) & 0xff)

    if is_negative:
        for idx, val in enumerate(b_int):
            if val < 0xff:
                b_int[idx] += 1
                break

            b_int[idx] = 0

    if is_negative and b_int[-1] == 0x7f:  # Two's complement corner case
        b_int.append(0xff)

    b_int.reverse()
    b_int = bytes(b_int)
    if tag:
        b_int = pack_asn1(TagClass.universal, False, TypeTagNumber.integer, b_int)

    return b_int


def pack_asn1_object_identifier(oid, tag=True):
    """
    Pack an Object Identifer as a string (1.2.x.y.z) as a byte string.

    :param oid: The OID as a string to pack.
    :return: The byte string of the packed OID.
    """
    b_oid = bytearray()
    oid_split = [int(i) for i in oid.split('.')]

    if len(oid_split) < 2:
        raise ValueError("An OID must have 2 or more elements split by '.'")

    # The first byte of the OID is the first 2 elements (x.y) as (x * 40) + y
    b_oid.append((oid_split[0] * 40) + oid_split[1])

    for val in oid_split[2:]:
        b_oid.extend(pack_asn1_octet_number(val))

    b_oid = bytes(b_oid)
    if tag:
        b_oid = pack_asn1(TagClass.universal, False, TypeTagNumber.object_identifier, b_oid)

    return b_oid


def pack_asn1_octet_number(num):
    """
    Packs a number into 1 or multiple octets depending on the size. The MSB (most significant byte) is set when the
    number cannot be encoded into 7 bits and indicates another octet is required.

    :param num: The number to pack into bytes.
    :return: A byte string of the packed number.
    """
    num_octets = bytearray()

    while num:
        # Get the 7 bit value of the number.
        octet_value = num & 0b01111111

        # Set the MSB if this isn't the first octet we are processing (overall last octet)
        if len(num_octets):
            octet_value |= 0b10000000

        num_octets.append(octet_value)

        # Shift the number by 7 bits as we've just processed them.
        num >>= 7

    # Finally we reverse the order so the higher octets are first.
    num_octets.reverse()

    return num_octets


def pack_asn1_octet_string(b_data, tag=True):
    """

    :param b_data:
    :param tag:
    :return:
    """
    if tag:
        b_data = pack_asn1(TagClass.universal, False, TypeTagNumber.octet_string, b_data)

    return b_data


def pack_asn1_sequence(sequence, tag=True):
    """

    :param sequence:
    :param tag:
    :return:
    """
    b_data = b"".join(sequence)
    if tag:
        b_data = pack_asn1(TagClass.universal, True, TypeTagNumber.sequence, b_data)

    return b_data


def unpack_asn1(b_data):
    """

    :param b_data:
    :return:
    """
    import base64
    octet1 = struct.unpack("B", b_data[:1])[0]
    tag_class = (octet1 & 0b11000000) >> 6
    constructed = bool(octet1 & 0b00100000)
    tag_number = octet1 & 0b00011111

    length_offset = 1
    if tag_number == 31:
        tag_number, octet_count = unpack_asn1_octet_number(b_data[1:])
        length_offset += octet_count

    b_data = b_data[length_offset:]

    length = struct.unpack("B", b_data[:1])[0]
    length_octets = 1

    if length & 0b10000000:
        # If the MSB is set then the length octet just contains the number of octets that encodes the actual length.
        length_octets += length & 0b01111111
        length = 0

        for idx in range(1, length_octets):
            octet_val = struct.unpack("B", b_data[idx:idx + 1])[0]
            length += octet_val << (8 * (length_octets - 1 - idx))

    remaining_data = b_data[length_octets + length:]
    b_data = b_data[length_octets:length_octets + length]
    return tag_class, constructed, tag_number, b_data, remaining_data


def unpack_asn1_bit_string(b_data):
    """

    :param b_data:
    :return:
    """
    # First octet is the number of unused bits in the last octet from the LSB.
    unused_bits = struct.unpack("B", b_data[:1])[0]
    last_octet = struct.unpack("B", b_data[-1])[0]
    last_octet = (last_octet >> unused_bits) << unused_bits

    return b_data[1:-1] + struct.pack("B", last_octet)


def unpack_asn1_enumerated(b_data):
    """

    :param b_data:
    :return:
    """
    return unpack_asn1_integer(b_data)


def unpack_asn1_integer(b_data):
    """

    :param b_data:
    :return:
    """
    length = len(b_data)

    if length == 1:
        # The MSB denotes whether the number is negative or not.
        value = struct.unpack("B", b_data)[0]
        is_negative = bool(value & 0b10000000)
    else:
        is_negative = False
        value = 0
        idx = 0

        while idx != length:
            b_val = b_data[idx:idx + 1]

            # The first octet can be \x00 which indicate the value is a positive number regardless of the MSB in the
            # next octet.
            if idx == 0 and b_val == b"\x00":
                idx += 1
                continue

            element = struct.unpack("B", b_val)[0]

            # If the first octet's MSB is set then the number is a negative number.
            if idx == 0 and element & 0b10000000:
                is_negative = True
                element &= 0b01111111

            value = (value << 8) + value
            idx += 1

    if is_negative:
        value *= -1

    return value


def unpack_asn1_object_identifier(b_data):
    """

    :param b_data:
    :return:
    """
    first_element = struct.unpack("B", b_data[:1])[0]
    second_element = first_element % 40
    ids = [(first_element - second_element) // 40, second_element]

    idx = 1
    while idx != len(b_data):
        oid, octet_len = unpack_asn1_octet_number(b_data[idx:])
        ids.append(oid)
        idx += octet_len

    return ".".join([str(i) for i in ids])


def unpack_asn1_octet_number(b_data):
    """

    :param b_data:
    :return:
    """
    i = 0
    idx = 0
    while True:
        element = struct.unpack("B", b_data[idx:idx + 1])[0]
        idx += 1

        i = (i << 7) + (element & 0b01111111)
        if not element & 0b10000000:
            break

    return i, idx
