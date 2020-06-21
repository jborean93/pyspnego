# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import pytest
import re

import spnego.gss
import spnego.iov


def test_build_iov_list(kerb_cred):
    c = spnego.gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')
    actual = c._build_iov_list([
        (spnego.iov.BufferType.header, b"\x01"),
        (spnego.iov.BufferType.data, 1),
        (spnego.iov.BufferType.padding, True),
        spnego.iov.BufferType.header,
        spnego.iov.BufferType.stream,
        b"\x02",
    ])

    assert len(actual) == 6
    assert actual[0] == (spnego.iov.BufferType.header, False, b"\x01")
    assert actual[1] == (spnego.iov.BufferType.data, False, b"\x00")
    assert actual[2] == (spnego.iov.BufferType.padding, False, b"\x00")
    assert actual[3] == (spnego.iov.BufferType.header, True, None)
    assert actual[4] == (spnego.iov.BufferType.stream, False, None)
    assert actual[5] == (spnego.iov.BufferType.data, False, b"\x02")


def test_build_iov_list_invalid_tuple(kerb_cred):
    c = spnego.gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry tuple must contain 2 values, the type and data, see IOVBuffer."
    with pytest.raises(ValueError, match=expected):
        c._build_iov_list([(1, 2, 3)])


def test_build_iov_list_invalid_buffer_type(kerb_cred):
    c = spnego.gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry[0] must specify the BufferType as an int"
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([(b"", b"")])


def test_build_iov_list_invalid_data(kerb_cred):
    c = spnego.gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry[1] must specify the buffer bytes, length of the buffer, or whether it is auto allocated."
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([(1, u"data")])


def test_build_iov_list_invalid_value(kerb_cred):
    c = spnego.gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry must be a IOVBuffer tuple, int, or bytes"
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([None])
