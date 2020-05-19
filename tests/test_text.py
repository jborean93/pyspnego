# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import sys

import pytest

import spnego._text as text


class Obj:

    def __init__(self, str=None, repr=None):
        self.str = str
        self.repr = repr

    def __eq__(self, other):
        return self.str == other.str and self.repr == other.repr

    def __str__(self):
        return self.str

    def __repr__(self):
        return self.repr


class ObjRepr:

    def __init__(self, repr=None):
        self.repr = repr

    def __repr__(self):
        return self.repr


class ObjUnicodeError:

    def __str__(self):
        return u"café".encode('ascii')

    def __repr__(self):
        return u"café".encode('ascii')


def test_to_bytes_from_bytes():
    actual = text.to_bytes(b"\xFF\x00\x7F\x80")

    assert actual == b"\xFF\x00\x7F\x80"


@pytest.mark.parametrize('value, expected', [
    (u"cafe", b"cafe"),
    (u"café", b"caf\xc3\xa9"),
    (u"ÜseӜ", b"\x55\xCC\x88\x73\x65\xD3\x9C"),
])
def test_to_bytes_from_text(value, expected):
    actual = text.to_bytes(value)

    assert actual == expected


def test_to_bytes_encoding():
    actual = text.to_bytes(u"café", encoding='windows-1252')

    assert actual == b"caf\xe9"


def test_to_bytes_errors():
    with pytest.raises(UnicodeEncodeError, match="codec can't encode character"):
        text.to_bytes(u"café", encoding='ascii')

    actual = text.to_bytes(u"café", encoding='ascii', errors='replace')

    assert actual == b"caf?"


def test_to_bytes_nonstr():
    actual = text.to_bytes(Obj(str=text.to_native(u"café")))

    assert actual == b"caf\xc3\xa9"


def test_to_bytes_nonstr_default():
    actual = text.to_bytes(Obj())

    assert actual == b""


def test_to_bytes_nonstr_repr():
    actual = text.to_bytes(ObjRepr(repr=text.to_native(u"café")))

    assert actual == b"caf\xc3\xa9"


def test_to_bytes_nonstr_unicode_error():
    actual = text.to_bytes(ObjUnicodeError())

    assert actual == b""


def test_to_bytes_nonstr_passthru():
    actual = text.to_bytes(Obj(), nonstring='passthru')

    assert actual == Obj()


def test_to_bytes_nonstr_empty():
    actual = text.to_bytes(Obj(), nonstring='empty')

    assert actual == b""


def test_to_bytes_nonstr_invalid():
    with pytest.raises(ValueError, match="Invalid nonstring value"):
        text.to_bytes(Obj(), nonstring='invalid')


def test_to_text_from_text():
    actual = text.to_text(u"café")

    assert actual == u"café"


@pytest.mark.parametrize('value, expected', [
    (b"cafe", u"cafe"),
    (b"caf\xc3\xa9", u"café"),
    (b"\x55\xCC\x88\x73\x65\xD3\x9C", u"ÜseӜ"),
])
def test_to_text_from_bytes(value, expected):
    actual = text.to_text(value)

    assert actual == expected


def test_to_text_encoding():
    actual = text.to_text(b"caf\xe9", encoding='windows-1252')

    assert actual == u"café"


def test_to_text_errors():
    with pytest.raises(UnicodeError, match="codec can't decode byte 0xff"):
        text.to_text(b"caf\xFF")

    actual = text.to_text(b"caf\xFF", errors='replace')

    assert actual == u"caf�"


def test_to_text_nonstr():
    actual = text.to_text(Obj(str=text.to_native(u"café")))

    assert actual == u"café"


def test_to_text_nonstr_unicode():
    class ObjUnicode:

        def __unicode__(self):
            return u"café"

    actual = text.to_text(ObjUnicode())

    assert actual == u"café"


def test_to_text_nonstr_default():
    actual = text.to_text(Obj())

    assert actual == u""


def test_to_text_nonstr_repr():
    actual = text.to_text(ObjRepr(repr=text.to_native(u"café")))

    assert actual == u"café"


def test_to_text_nonstr_unicode_error():
    actual = text.to_text(ObjUnicodeError())

    assert actual == u""


def test_to_text_nonstr_passthru():
    actual = text.to_text(Obj(), nonstring='passthru')

    assert actual == Obj()


def test_to_text_nonstr_empty():
    actual = text.to_text(Obj(), nonstring='empty')

    assert actual == u""


def test_to_text_nonstr_invalid():
    with pytest.raises(ValueError, match="Invalid nonstring value"):
        text.to_text(Obj(), nonstring='invalid')


@pytest.mark.skipif(sys.version_info[0] == 3, reason='to_native is Python version specific')
def test_to_native_py2():
    actual = text.to_native(u"café")

    assert isinstance(actual, str)
    assert isinstance(actual, bytes)
    assert actual == b"caf\xc3\xa9"


@pytest.mark.skipif(sys.version_info[0] == 2, reason='to_native is Python version specific')
def test_to_native_py3():
    actual = text.to_native(u"café")

    assert isinstance(actual, str)
    assert actual == u"café"
