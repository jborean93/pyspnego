# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import collections
import os
import pytest
import re

import spnego
import spnego.gss
import spnego.iov

from spnego.exceptions import (
    FeatureMissingError,
)


def test_gss_sasl_description_fail(mocker, monkeypatch):
    gssapi = pytest.importorskip('gssapi')
    SASLResult = collections.namedtuple('SASLResult', ['mech_description'])

    mock_inquire_sasl = mocker.MagicMock()
    mock_inquire_sasl.side_effect = [Exception, SASLResult(b'result')]
    monkeypatch.setattr(gssapi.raw, 'inquire_saslname_for_mech', mock_inquire_sasl)

    actual = spnego.gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3'))
    assert actual is None

    actual = spnego.gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3'))
    assert actual is None

    actual = spnego.gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3.4'))
    assert actual == b'result'

    actual = spnego.gss._gss_sasl_description(gssapi.OID.from_int_seq('1.2.3.4'))
    assert actual == b'result'

    assert mock_inquire_sasl.call_count == 2


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


def test_no_gssapi_library(monkeypatch):
    monkeypatch.setattr(spnego.gss, 'HAS_GSSAPI', False)

    with pytest.raises(ImportError, match="GSSAPIProxy requires the Python gssapi library"):
        spnego.gss.GSSAPIProxy()


@pytest.mark.skipif(not spnego.gss.HAS_GSSAPI, reason='Requires the gssapi library to be installed for testing')
def test_gssapi_no_kerberos(monkeypatch):
    def available_protocols(*args, **kwargs):
        return ['negotiate', 'ntlm']

    monkeypatch.setattr(spnego.gss, 'HAS_GSSAPI', True)
    monkeypatch.setattr(spnego.gss, '_available_protocols', available_protocols)

    with pytest.raises(FeatureMissingError, match="The Python gssapi library is not installed so Kerberos cannot be "
                                                  "negotiated."):
        spnego.gss.GSSAPIProxy(None, None, options=spnego.NegotiateOptions.negotiate_kerberos)


@pytest.mark.skipif(os.name == 'nt', reason='Cannot read from temp file on Windows due to lack of sharing flags.')
def test_config_with_forwardable():
    with spnego.gss._krb5_conf(True):
        conf_path = os.environ['KRB5_CONFIG'].split(':')[0]
        with open(conf_path, mode='rb') as fd:
            actual = fd.read()

        assert actual == b"[libdefaults]\nforwardable = true\n"

    assert not os.path.exists(conf_path)


def test_config_without_forwardable():
    with spnego.gss._krb5_conf(False):
        assert 'KRB5_CONFIG' not in list(os.environ.keys())


@pytest.mark.parametrize('original_value, new_value, expected', [
    (None, 'krb5.conf', 'krb5.conf:/etc/krb5.conf'),
    ('/etc/krb5.conf', 'krb5.conf', 'krb5.conf:/etc/krb5.conf'),
    ('/var/lib/krb5.conf:/etc/krb5.conf', '/opt/krb5.conf', '/opt/krb5.conf:/var/lib/krb5.conf:/etc/krb5.conf'),
])
def test_env_var(original_value, new_value, expected):
    env_name = 'TEST_SPNEGO_ENV'
    if original_value:
        os.environ[env_name] = original_value

    try:
        with spnego.gss._env_path(env_name, new_value, '/etc/krb5.conf'):
            assert os.environ[env_name] == expected

        if original_value:
            assert os.environ[env_name] == original_value

        else:
            assert env_name not in list(os.environ.keys())

    finally:
        if os.environ.get(env_name):
            del os.environ[env_name]
