# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
import typing

import pytest

import spnego._text as text


class Obj:
    def __init__(self, str: typing.Optional[str] = None, repr: typing.Optional[str] = None) -> None:
        self.str = str
        self.repr = repr

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, Obj) and self.str == other.str and self.repr == other.repr

    def __str__(self) -> str:
        return self.str  # type: ignore[return-value] # Testing this scenario

    def __repr__(self) -> str:
        return self.repr  # type: ignore[return-value] # Testing this scenario


class ObjRepr:
    def __init__(self, repr: typing.Optional[str] = None) -> None:
        self.repr = repr

    def __repr__(self) -> str:
        return self.repr  # type: ignore[return-value] # Testing this scenario


class ObjUnicodeError:
    def __str__(self) -> str:
        return "café".encode("ascii")  # type: ignore[return-value] # Testing this scenario

    def __repr__(self) -> str:
        return "café".encode("ascii")  # type: ignore[return-value] # Testing this scenario


def test_to_bytes_from_bytes():
    actual = text.to_bytes(b"\xFF\x00\x7F\x80")

    assert actual == b"\xFF\x00\x7F\x80"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("cafe", b"cafe"),
        ("café", b"caf\xc3\xa9"),
        ("ÜseӜ", b"\x55\xCC\x88\x73\x65\xD3\x9C"),
    ],
)
def test_to_bytes_from_text(value, expected):
    actual = text.to_bytes(value)

    assert actual == expected


def test_to_bytes_encoding():
    actual = text.to_bytes("café", encoding="windows-1252")

    assert actual == b"caf\xe9"


def test_to_bytes_errors():
    with pytest.raises(UnicodeEncodeError, match="codec can't encode character"):
        text.to_bytes("café", encoding="ascii")

    actual = text.to_bytes("café", encoding="ascii", errors="replace")

    assert actual == b"caf?"


def test_to_bytes_nonstr():
    actual = text.to_bytes(Obj(str="café"))

    assert actual == b"caf\xc3\xa9"


def test_to_bytes_nonstr_default():
    actual = text.to_bytes(Obj())

    assert actual == b""


def test_to_bytes_nonstr_repr():
    actual = text.to_bytes(ObjRepr(repr="café"))

    assert actual == b"caf\xc3\xa9"


def test_to_bytes_nonstr_unicode_error():
    actual = text.to_bytes(ObjUnicodeError())

    assert actual == b""


def test_to_bytes_nonstr_passthru():
    actual = text.to_bytes(Obj(), nonstring="passthru")

    assert actual == Obj()


def test_to_bytes_nonstr_empty():
    actual = text.to_bytes(Obj(), nonstring="empty")

    assert actual == b""


def test_to_bytes_nonstr_invalid():
    with pytest.raises(ValueError, match="Invalid nonstring value"):
        text.to_bytes(Obj(), nonstring="invalid")


def test_to_text_from_text():
    actual = text.to_text("café")

    assert actual == "café"


@pytest.mark.parametrize(
    "value, expected",
    [
        (b"cafe", "cafe"),
        (b"caf\xc3\xa9", "café"),
        (b"\x55\xCC\x88\x73\x65\xD3\x9C", "ÜseӜ"),
    ],
)
def test_to_text_from_bytes(value, expected):
    actual = text.to_text(value)

    assert actual == expected


def test_to_text_encoding():
    actual = text.to_text(b"caf\xe9", encoding="windows-1252")

    assert actual == "café"


def test_to_text_errors():
    with pytest.raises(UnicodeError, match="codec can't decode byte 0xff"):
        text.to_text(b"caf\xFF")

    actual = text.to_text(b"caf\xFF", errors="replace")

    assert actual == "caf�"


def test_to_text_nonstr():
    actual = text.to_text(Obj(str="café"))

    assert actual == "café"


def test_to_text_nonstr_unicode():
    class ObjUnicode:
        def __unicode__(self):
            return "café"

    actual = text.to_text(ObjUnicode())

    assert actual == "café"


def test_to_text_nonstr_default():
    actual = text.to_text(Obj())

    assert actual == ""


def test_to_text_nonstr_repr():
    actual = text.to_text(ObjRepr(repr="café"))

    assert actual == "café"


def test_to_text_nonstr_unicode_error():
    actual = text.to_text(ObjUnicodeError())

    assert actual == ""


def test_to_text_nonstr_passthru():
    actual = text.to_text(Obj(), nonstring="passthru")

    assert actual == Obj()


def test_to_text_nonstr_empty():
    actual = text.to_text(Obj(), nonstring="empty")

    assert actual == ""


def test_to_text_nonstr_invalid():
    with pytest.raises(ValueError, match="Invalid nonstring value"):
        text.to_text(Obj(), nonstring="invalid")
