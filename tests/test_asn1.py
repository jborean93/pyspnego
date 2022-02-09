# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime
import re
import typing

import pytest

import spnego._asn1 as asn1

ASN1_TAG_TESTS = [
    # Simple universal
    (asn1.TagClass.universal, False, asn1.TypeTagNumber.octet_string, b"\x00", b"\x04\x01\x00"),
    # Constructed value
    (asn1.TagClass.universal, True, asn1.TypeTagNumber.octet_string, b"\x00\x00", b"\x24\x02\x00\x00"),
    # Large tag number
    (asn1.TagClass.application, True, 1024, b"\x00\x00", b"\x7F\x88\x00\x02\x00\x00"),
    (asn1.TagClass.application, True, 1048576, b"\x00\x00", b"\x7F\xC0\x80\x00\x02\x00\x00"),
    # Long length
    (asn1.TagClass.universal, False, asn1.TypeTagNumber.octet_string, b"\x00" * 127, b"\x04\x7F" + (b"\x00" * 127)),
    (asn1.TagClass.universal, False, asn1.TypeTagNumber.octet_string, b"\x00" * 128, b"\x04\x81\x80" + (b"\x00" * 128)),
    (
        asn1.TagClass.universal,
        False,
        asn1.TypeTagNumber.octet_string,
        b"\x00" * 1024,
        b"\x04\x82\x04\x00" + (b"\x00" * 1024),
    ),
]

# openssl asn1parse -genstr 'INTEGER:<val>' -out test && hexdump -C test && rm test
INTEGER_TESTS = [  # INTEGER has weird rules that I don't fully understand, use a test of test cases.
    (-748591, b"\x02\x03\xF4\x93\xD1"),
    (-32769, b"\x02\x03\xFF\x7F\xFF"),
    (-32768, b"\x02\x02\x80\x00"),
    (-32767, b"\x02\x02\x80\x01"),
    (-257, b"\x02\x02\xFE\xFF"),
    (-256, b"\x02\x02\xFF\x00"),
    (-255, b"\x02\x02\xFF\x01"),
    (-129, b"\x02\x02\xFF\x7F"),
    (-128, b"\x02\x01\x80"),
    (-127, b"\x02\x01\x81"),
    (-17, b"\x02\x01\xEF"),
    (-16, b"\x02\x01\xF0"),
    (-10, b"\x02\x01\xF6"),
    (-1, b"\x02\x01\xFF"),
    (0, b"\x02\x01\x00"),
    (1, b"\x02\x01\x01"),
    (10, b"\x02\x01\x0A"),
    (16, b"\x02\x01\x10"),
    (17, b"\x02\x01\x11"),
    (127, b"\x02\x01\x7F"),
    (128, b"\x02\x02\x00\x80"),
    (129, b"\x02\x02\x00\x81"),
    (255, b"\x02\x02\x00\xFF"),
    (256, b"\x02\x02\x01\x00"),
    (257, b"\x02\x02\x01\x01"),
    (32767, b"\x02\x02\x7F\xFF"),
    (32768, b"\x02\x03\x00\x80\x00"),
    (32769, b"\x02\x03\x00\x80\x01"),
    (748591, b"\x02\x03\x0B\x6C\x2F"),
]

OID_TESTS = [
    ("1.2", b"\x06\x01\x2A"),
    ("1.2.3", b"\x06\x02\x2A\x03"),
    ("1.2.3.1024.2", b"\x06\x05\x2A\x03\x88\x00\x02"),
]


def test_tag_class_native_labels():
    actual = asn1.TagClass.native_labels()

    assert isinstance(actual, dict)
    assert actual[asn1.TagClass.universal] == "Universal"


def test_type_tag_number_native_labels():
    actual = asn1.TypeTagNumber.native_labels()

    assert isinstance(actual, dict)
    assert actual[asn1.TypeTagNumber.end_of_content] == "End-of-Content (EOC)"


@pytest.mark.parametrize(
    "value, tag_class, tag_number, expected",
    [
        (
            asn1.unpack_asn1(asn1.pack_asn1_octet_string(b"\x00\x01"))[0],
            asn1.TagClass.universal,
            asn1.TypeTagNumber.octet_string,
            b"\x00\x01",
        ),
        (b"\x00\x01", asn1.TagClass.universal, asn1.TypeTagNumber.octet_string, b"\x00\x01"),
        (asn1.ASN1Value(asn1.TagClass.application, True, 1023, b"\x00"), asn1.TagClass.application, 1023, b"\x00"),
    ],
)
def test_extract_asn1_tlv(value, tag_class, tag_number, expected):
    actual = asn1.extract_asn1_tlv(value, tag_class, tag_number)
    assert actual == expected


def test_extract_asn1_tlv_invalid_universal_class():
    expected = (
        "Invalid ASN.1 OCTET STRING tags, actual tag class TagClass.universal and tag number " "TypeTagNumber.integer"
    )
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.extract_asn1_tlv(
            asn1.ASN1Value(asn1.TagClass.universal, False, asn1.TypeTagNumber.integer, b"\x01"),
            asn1.TagClass.universal,
            asn1.TypeTagNumber.octet_string,
        )


def test_extract_asn1_invalid_other_class():
    expected = (
        "Invalid ASN.1 tags, actual tag TagClass.application and number 1024, expecting class "
        "TagClass.application and number 512"
    )
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.extract_asn1_tlv(
            asn1.ASN1Value(asn1.TagClass.application, True, 1024, b"\x01"), asn1.TagClass.application, 512
        )


def test_get_sequence_value():
    input_sequence = asn1.pack_asn1_sequence(
        [asn1.pack_asn1(asn1.TagClass.context_specific, True, 1, asn1.pack_asn1_integer(1))]
    )
    output_sequence = asn1.unpack_asn1_tagged_sequence(asn1.unpack_asn1(input_sequence)[0])

    actual = asn1.get_sequence_value(output_sequence, 1, "Structure", "field-name", asn1.unpack_asn1_integer)
    assert actual == 1


def test_get_sequence_value_raw():
    input_sequence = asn1.pack_asn1_sequence(
        [asn1.pack_asn1(asn1.TagClass.context_specific, True, 1, asn1.pack_asn1_integer(1))]
    )
    output_sequence = asn1.unpack_asn1_tagged_sequence(asn1.unpack_asn1(input_sequence)[0])

    actual = asn1.get_sequence_value(output_sequence, 1, "Structure")
    assert actual == asn1.ASN1Value(asn1.TagClass.universal, False, asn1.TypeTagNumber.integer, b"\x01")


def test_get_sequence_value_no_tag():
    input_sequence = asn1.pack_asn1_sequence(
        [asn1.pack_asn1(asn1.TagClass.context_specific, True, 1, asn1.pack_asn1_integer(1))]
    )
    output_sequence = asn1.unpack_asn1_tagged_sequence(asn1.unpack_asn1(input_sequence)[0])

    actual = asn1.get_sequence_value(output_sequence, 2, "Structure")
    assert actual is None


def test_get_sequence_value_failure_with_field_name():
    input_sequence = asn1.pack_asn1_sequence(
        [asn1.pack_asn1(asn1.TagClass.context_specific, True, 1, asn1.pack_asn1_integer(1))]
    )
    output_sequence = asn1.unpack_asn1_tagged_sequence(asn1.unpack_asn1(input_sequence)[0])

    expected = (
        "Failed unpacking field-name in Structure: Invalid ASN.1 OCTET STRING tags, actual tag class "
        "TagClass.universal and tag number TypeTagNumber.integer"
    )
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.get_sequence_value(output_sequence, 1, "Structure", "field-name", asn1.unpack_asn1_octet_string)


def test_get_sequence_value_failure_without_field_name():
    input_sequence = asn1.pack_asn1_sequence(
        [asn1.pack_asn1(asn1.TagClass.context_specific, True, 1, asn1.pack_asn1_integer(1))]
    )
    output_sequence = asn1.unpack_asn1_tagged_sequence(asn1.unpack_asn1(input_sequence)[0])

    expected = (
        "Failed unpacking Structure: Invalid ASN.1 OCTET STRING tags, actual tag class "
        "TagClass.universal and tag number TypeTagNumber.integer"
    )
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.get_sequence_value(output_sequence, 1, "Structure", unpack_func=asn1.unpack_asn1_octet_string)


@pytest.mark.parametrize("tag_class, constructed, tag_number, data, expected", ASN1_TAG_TESTS)
def test_pack_asn1_tlv(tag_class, constructed, tag_number, data, expected):
    actual = asn1.pack_asn1(tag_class, constructed, tag_number, data)
    assert actual == expected


@pytest.mark.parametrize("tag_class, constructed, tag_number, data, value", ASN1_TAG_TESTS)
def test_unpack_asn1_tlv(tag_class, constructed, tag_number, data, value):
    actual = asn1.unpack_asn1(value)

    assert actual[0].tag_class == tag_class
    assert actual[0].constructed == constructed
    assert actual[0].tag_number == tag_number
    assert actual[0].b_data == data
    assert actual[1] == b""


def test_unpack_asn1_tlv_remaining_data():
    actual = asn1.unpack_asn1(b"\x04\x01\x00\x01")

    assert actual[0].tag_class == asn1.TagClass.universal
    assert not actual[0].constructed
    assert actual[0].tag_number == asn1.TypeTagNumber.octet_string
    assert actual[0].b_data == b"\x00"
    assert actual[1] == b"\x01"


def test_pack_asn1_tlv_invalid_class():
    expected = "tag_class must be between 0 and 3"
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.pack_asn1(10, False, 0, b"")  # type: ignore[arg-type]


def test_pack_asn1_bit_string():
    actual = asn1.pack_asn1_bit_string(b"\x01\x01")
    assert actual == b"\x03\x03\x00\x01\x01"


@pytest.mark.parametrize(
    "value, expected",
    [
        (b"\x03\x03\x00\x01\x01", b"\x01\x01"),
        (b"\x03\x03\x01\x01\x01", b"\x01\x00"),
    ],
)
def test_unpack_asn1_bit_string(value, expected):
    actual = asn1.unpack_asn1_bit_string(value[2:])
    assert actual == expected

    actual = asn1.unpack_asn1_bit_string(asn1.unpack_asn1(value)[0])
    assert actual == expected


def test_pack_asn1_general_string():
    actual = asn1.pack_asn1_general_string("cafe")
    assert actual == b"\x1B\x04\x63\x61\x66\x65"


def test_pack_asn1_enumerated():
    actual = asn1.pack_asn1_enumerated(1024)
    assert actual == b"\x0A\x02\x04\x00"


def test_unpack_asn1_enumerated():
    value = b"\x0A\x02\x04\x00"
    expected = 1024

    actual = asn1.unpack_asn1_enumerated(value[2:])
    assert actual == expected

    actual = asn1.unpack_asn1_enumerated(asn1.unpack_asn1(value)[0])
    assert actual == expected


def test_pack_asn1_general_string_encoding():
    actual = asn1.pack_asn1_general_string("café", encoding="utf-8")
    assert actual == b"\x1B\x05\x63\x61\x66\xC3\xA9"


def test_unpack_asn1_general_string():
    value = b"\x1B\x05\x63\x61\x66\xC3\xA9"
    expected = b"\x63\x61\x66\xC3\xA9"

    actual = asn1.unpack_asn1_general_string(value[2:])
    assert actual == expected

    actual = asn1.unpack_asn1_general_string(asn1.unpack_asn1(value)[0])
    assert actual == expected


@pytest.mark.parametrize("value, expected", INTEGER_TESTS)
def test_pack_asn1_integer(value, expected):
    actual = asn1.pack_asn1_integer(value)
    assert actual == expected

    actual_untagged = asn1.pack_asn1_integer(value, tag=False)
    assert actual_untagged == expected[2:]


@pytest.mark.parametrize("expected, value", INTEGER_TESTS)
def test_unpack_asn1_integer(expected, value):
    asn1_value = asn1.unpack_asn1(value)[0]
    actual = asn1.unpack_asn1_integer(asn1_value)
    assert actual == expected

    actual = asn1.unpack_asn1_integer(value[2:])
    assert actual == expected


@pytest.mark.parametrize("value, expected", OID_TESTS)
def test_pack_object_identifier(value, expected):
    actual = asn1.pack_asn1_object_identifier(value)
    assert actual == expected


def test_pack_object_identifier_invalid_value():
    expected = "An OID must have 2 or more elements split by '.'"
    with pytest.raises(ValueError, match=re.escape(expected)):
        asn1.pack_asn1_object_identifier("1")


@pytest.mark.parametrize("expected, value", OID_TESTS)
def test_unpack_object_identifier(expected, value):
    asn1_value = asn1.unpack_asn1(value)[0]
    actual = asn1.unpack_asn1_object_identifier(asn1_value)
    assert actual == expected

    actual = asn1.unpack_asn1_object_identifier(value[2:])
    assert actual == expected


def test_pack_asn1_sequence():
    inner_val = asn1.pack_asn1_octet_string(b"\x01\x02")
    actual = asn1.pack_asn1_sequence([inner_val, inner_val])

    assert actual == b"\x30\x08\x04\x02\x01\x02\x04\x02\x01\x02"


def test_unpack_asn1_sequence():
    value = b"\x30\x08\x04\x02\x01\x02\x04\x02\x01\x02"

    def actual_test(expected: typing.List) -> bool:
        assert isinstance(expected, list)

        for a in expected:
            assert isinstance(a, asn1.ASN1Value)
            assert a.tag_class == asn1.TagClass.universal
            assert not a.constructed
            assert a.tag_number == asn1.TypeTagNumber.octet_string
            assert a.b_data == b"\x01\x02"

        return True

    actual = asn1.unpack_asn1_sequence(value[2:])
    assert actual_test(actual)

    actual = asn1.unpack_asn1_sequence(asn1.unpack_asn1(value)[0])
    assert actual_test(actual)


def test_pack_asn1_octet_string():
    actual = asn1.pack_asn1_octet_string(b"\x01\x02")
    assert actual == b"\x04\x02\x01\x02"


def test_unpack_asn1_octet_string():
    value = b"\x04\x02\x01\x02"
    expected = b"\x01\x02"

    actual = asn1.unpack_asn1_octet_string(value[2:])
    assert actual == expected

    actual = asn1.unpack_asn1_octet_string(asn1.unpack_asn1(value)[0])
    assert actual == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (b"\x00", False),
        (b"\x01", True),
        (b"\x02", True),
    ],
)
def test_unpack_asn1_boolean(value, expected):
    actual = asn1.unpack_asn1_boolean(value)
    assert actual == expected

    actual = asn1.unpack_asn1_boolean(asn1.unpack_asn1(b"\x01\x01" + value)[0])
    assert actual == expected


@pytest.mark.parametrize(
    "value",
    [
        b"\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5A",
        b"\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x2E\x30\x30\x30\x30\x30\x30\x5A",
    ],
)
def test_unpack_asn1_generalized_time(value):
    expected = datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)

    actual = asn1.unpack_asn1_generalized_time(value)
    assert actual == expected

    packed_value = asn1.pack_asn1(asn1.TagClass.universal, False, asn1.TypeTagNumber.generalized_time, value)
    actual = asn1.unpack_asn1_generalized_time(asn1.unpack_asn1(packed_value)[0])
    assert actual == expected


def test_unpack_asn1_generalized_time_format_err():
    expected = "time data '1970' does not match format"
    with pytest.raises(ValueError, match=expected):
        asn1.unpack_asn1_generalized_time(b"\x31\x39\x37\x30")
