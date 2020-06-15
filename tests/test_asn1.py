# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import pytest

import spnego._asn1 as asn1


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


@pytest.mark.parametrize('value, expected', INTEGER_TESTS)
def test_pack_asn1_integer(value, expected):
    actual = asn1.pack_asn1_integer(value)
    assert actual == expected

    actual_untagged = asn1.pack_asn1_integer(value, tag=False)
    assert actual_untagged == expected[2:]


@pytest.mark.parametrize('expected, value', INTEGER_TESTS)
def test_unpack_asn1_integer(expected, value):
    asn1_value = asn1.unpack_asn1(value)[0]
    actual = asn1.unpack_asn1_integer(asn1_value)
    assert actual == expected

    actual = asn1.unpack_asn1_integer(value[2:])
    assert actual == expected
