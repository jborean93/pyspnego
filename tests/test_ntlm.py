# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import os
import pytest
import re
import socket

import spnego
import spnego.channel_bindings
import spnego.gss
import spnego.ntlm as ntlm
import spnego.sspi

from spnego._context import (
    FeatureMissingError,
)

from spnego._text import (
    to_bytes,
    to_native,
    to_text,
)

from spnego.exceptions import (
    BadBindingsError,
    InvalidTokenError,
    OperationNotAvailableError,
    SpnegoError,
    UnsupportedQop,
)

from .conftest import get_data


def test_get_credential_file_no_env_var():
    actual = ntlm._get_credential_file()
    assert actual is None


def test_get_credential_file_env_var_missing_file(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')

    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))

    actual = ntlm._get_credential_file()
    assert actual is None


def test_get_credential_file(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    with open(tmp_creds, mode='wb') as fd:
        fd.write(b"data")

    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))

    actual = ntlm._get_credential_file()
    assert actual == to_text(tmp_creds)


@pytest.mark.parametrize('line, username, domain, lm_hash, nt_hash', [
    ('domain:Username:password', 'username', 'domain',
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    ('fake\ndomain:username:password', 'username', 'domain',  # newline or garbage data  in file won't fail
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    (':username@DOMAIN.COM:password', 'username@DOMAIN.COM', None,
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    ('testuser:1000:278623D830DABE161104594F8C2EF12B:C3C6F4FD8A02A6C1268F1A8074B6E7E0:[U]:LCT-1589398321',
     'testuser', None, '278623D830DABE161104594F8C2EF12B', 'C3C6F4FD8A02A6C1268F1A8074B6E7E0'),
    ('TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321',
     'testuser', 'testdom', '4588C64B89437893AAD3B435B51404EE', '65202355FA01AEF26B89B19E00F52679'),
    ('TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321',
     'testuser', 'testdom', '4588C64B89437893AAD3B435B51404EE', '65202355FA01AEF26B89B19E00F52679'),
    ('testuser@TESTDOM.COM:1000:00000000000000000000000000000000:8ADB9B997580D69E69CAA2BBB68F4697:[U]:LCT-1589398321',
     'testuser@testdom.com', '', '00000000000000000000000000000000', '8ADB9B997580D69E69CAA2BBB68F4697'),
])
def test_get_credential_from_file(line, username, domain, lm_hash, nt_hash, tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))
    with open(tmp_creds, mode='wb') as fd:
        fd.write(to_bytes(line))

    actual = ntlm._NTLMCredential(username, domain)

    assert actual.username == username
    assert actual.domain == domain
    assert actual.lm_hash == base64.b16decode(lm_hash)
    assert actual.nt_hash == base64.b16decode(nt_hash)


def test_get_credential_from_file_no_matches(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))
    with open(tmp_creds, mode='wb') as fd:
        fd.write(b'domain:username:password')

    with pytest.raises(SpnegoError, match="Failed to find any matching credential in NTLM_USER_FILE "
                                          "credential store."):
        ntlm._NTLMCredential("username", "fake")


@pytest.mark.parametrize('level', [-1, 6])
def test_invalid_lm_compat_level(level, monkeypatch):
    monkeypatch.setenv('LM_COMPAT_LEVEL', to_native(level))

    expected = "Invalid LM_COMPAT_LEVEL %s, must be between 0 and 5" % level
    with pytest.raises(SpnegoError, match=re.escape(expected)):
        ntlm.NTLMProxy("user", "pass")


@pytest.mark.parametrize('usage', ['initiate', 'accept'])
def test_context_no_store(usage):
    with pytest.raises(OperationNotAvailableError, match="Retrieving NTLM store without NTLM_USER_FILE set to a "
                                                         "filepath"):
        ntlm.NTLMProxy(None, None, usage=usage)


def test_iov_available():
    assert ntlm.NTLMProxy.iov_available() is False


def test_ntlm_invalid_usage():
    with pytest.raises(ValueError, match="Invalid usage 'test', must be initiate or accept"):
        ntlm.NTLMProxy('user', 'pass', usage='test')


def test_ntlm_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid protocol 'fake', must be ntlm, kerberos, or negotiate"):
        ntlm.NTLMProxy('user', 'pass', protocol='fake')


def test_ntlm_iov_not_available():
    expected = "The system is missing the GSSAPI IOV extension headers or NTLM is being requested, cannot utilitze " \
               "wrap_iov and unwrap_iov"
    with pytest.raises(FeatureMissingError, match=re.escape(expected)):
        ntlm.NTLMProxy('user', 'pass', options=spnego.NegotiateOptions.wrapping_iov)


def test_ntlm_wrap_qop_invalid():
    n = ntlm.NTLMProxy('user', 'pass')
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.wrap(b"data", qop=1)


def test_ntlm_wrap_no_sign_or_seal():
    n = ntlm.NTLMProxy('user', 'pass')
    with pytest.raises(OperationNotAvailableError, match="NTLM wrap without integrity or confidentiality"):
        n.wrap(b"data")


def test_ntlm_wrap_iov_fail():
    n = ntlm.NTLMProxy('user', 'pass')
    with pytest.raises(OperationNotAvailableError, match="NTLM does not offer IOV wrapping"):
        n.wrap_iov([])


def test_ntlm_sign_qop_invalid():
    n = ntlm.NTLMProxy('user', 'pass')
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.sign(b"data", qop=1)


def test_ntlm_no_encoding_flags():
    negotiate = memoryview(bytearray(get_data('ntlm_negotiate')))
    negotiate[12:16] = b"\x00\x00\x00\x00"

    n = ntlm.NTLMProxy('user', 'pass')
    with pytest.raises(SpnegoError, match="Neither NEGOTIATE_OEM or NEGOTIATE_UNICODE flags were set, cannot derive "
                                          "encoding for text fields"):
        n._step_accept_negotiate(negotiate.tobytes())


@pytest.mark.parametrize('client_opt, present', [
    (spnego.NegotiateOptions.use_ntlm, False),
    (spnego.NegotiateOptions.use_ntlm, True),
    (spnego.NegotiateOptions.use_gssapi, True),
    (spnego.NegotiateOptions.use_sspi, True),
])
def test_ntlm_bad_bindings(client_opt, present, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi:
        if 'ntlm' not in spnego.gss.GSSAPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through GSSAPI')

    elif client_opt & spnego.NegotiateOptions.use_sspi:
        if 'ntlm' not in spnego.sspi.SSPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through SSPI')

    initiator_cbt = None
    if present:
        initiator_cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-host-data:bad")

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), options=client_opt, protocol='ntlm',
                      channel_bindings=initiator_cbt)

    acceptor_cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-host-data:test")
    s = spnego.server(None, None, options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm',
                      channel_bindings=acceptor_cbt)

    auth = c.step(s.step(c.step()))

    if present:
        expected = "Acceptor bindings do not match initiator bindings"

    else:
        expected = "Acceptor bindings specified but not present in initiator response"

    with pytest.raises(BadBindingsError, match=expected):
        s.step(auth)


def test_ntlm_bad_mic(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(),
                      options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm')
    s = spnego.server(None, None, options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm')

    auth = memoryview(bytearray(c.step(s.step(c.step()))))
    auth[64:80] = b"\x01" * 16

    with pytest.raises(InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        s.step(auth.tobytes())


def test_ntlm_no_key_exch(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(),
                      options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm')
    s = spnego.server(None, None, options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm')

    c._context_req &= ~0x40000000  # NTLMSSP_NEGOTIATE_KEY_EXCH

    auth = c.step(s.step(c.step()))
    s.step(auth)

    # Make sure EncryptedRandomSessionKeyFields was set to 0 (no KEY_EXCH).
    assert auth[52:54] == b"\x00\x00"

    plaintext = os.urandom(32)

    c_wrap_result = c.wrap(plaintext)
    assert c_wrap_result.encrypted
    assert c_wrap_result.data != plaintext

    s_unwrap_result = s.unwrap(c_wrap_result.data)
    assert s_unwrap_result.data == plaintext
    assert s_unwrap_result.encrypted

    plaintext = os.urandom(17)

    s_wrap_result = s.wrap(plaintext)
    assert s_wrap_result.encrypted
    assert s_wrap_result.data != plaintext

    c_unwrap_result = c.unwrap(s_wrap_result.data)
    assert c_unwrap_result.data == plaintext
    assert c_unwrap_result.encrypted

    plaintext = os.urandom(3)
    c_sig = c.sign(plaintext)
    s.verify(plaintext, c_sig)

    plaintext = os.urandom(9)
    s_sig = s.sign(plaintext)
    c.verify(plaintext, s_sig)
