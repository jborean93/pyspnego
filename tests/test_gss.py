# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import collections
import re

import pytest

import spnego
import spnego._gss
import spnego.iov
from spnego.exceptions import FeatureMissingError


def test_gss_sasl_description_fail(mocker, monkeypatch):
    gssapi = pytest.importorskip('gssapi')
    SASLResult = collections.namedtuple('SASLResult', ['mech_description'])

    mock_inquire_sasl = mocker.MagicMock()
    mock_inquire_sasl.side_effect = [Exception, SASLResult(b'result')]
    monkeypatch.setattr(gssapi.raw, 'inquire_saslname_for_mech', mock_inquire_sasl)

    actual = spnego._gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3'))
    assert actual is None

    actual = spnego._gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3'))
    assert actual is None

    actual = spnego._gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3.4'))
    assert actual == b'result'

    actual = spnego._gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3.4'))
    assert actual == b'result'

    assert mock_inquire_sasl.call_count == 2


def test_build_iov_list(kerb_cred):
    c = spnego._gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')
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
    c = spnego._gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry tuple must contain 2 values, the type and data, see IOVBuffer."
    with pytest.raises(ValueError, match=expected):
        c._build_iov_list([(1, 2, 3)])


def test_build_iov_list_invalid_buffer_type(kerb_cred):
    c = spnego._gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry[0] must specify the BufferType as an int"
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([(b"", b"")])


def test_build_iov_list_invalid_data(kerb_cred):
    c = spnego._gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry[1] must specify the buffer bytes, length of the buffer, or whether it is auto allocated."
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([(1, "data")])


def test_build_iov_list_invalid_value(kerb_cred):
    c = spnego._gss.GSSAPIProxy(kerb_cred.user_princ, protocol='kerberos')

    expected = "IOV entry must be a IOVBuffer tuple, int, or bytes"
    with pytest.raises(ValueError, match=re.escape(expected)):
        c._build_iov_list([None])


def test_no_gssapi_library(monkeypatch):
    monkeypatch.setattr(spnego._gss, 'HAS_GSSAPI', False)

    with pytest.raises(ImportError, match="GSSAPIProxy requires the Python gssapi library"):
        spnego._gss.GSSAPIProxy()


@pytest.mark.skipif(not spnego._gss.HAS_GSSAPI, reason='Requires the gssapi library to be installed for testing')
def test_gssapi_no_kerberos(monkeypatch):
    def available_protocols(*args, **kwargs):
        return ['negotiate', 'ntlm']

    monkeypatch.setattr(spnego._gss, 'HAS_GSSAPI', True)
    monkeypatch.setattr(spnego._gss, '_available_protocols', available_protocols)

    with pytest.raises(FeatureMissingError, match="The Python gssapi library is not installed so Kerberos cannot be "
                                                  "negotiated."):
        spnego._gss.GSSAPIProxy(None, None, options=spnego.NegotiateOptions.negotiate_kerberos)
