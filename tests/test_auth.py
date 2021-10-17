# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import socket
import ssl

import pytest

import spnego
import spnego._credssp
import spnego._gss
import spnego._sspi
import spnego.channel_bindings
import spnego.iov
import spnego.tls
from spnego._context import (
    IOVUnwrapResult,
    IOVWrapResult,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
)
from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1
from spnego._spnego import NegTokenResp, unpack_token
from spnego.exceptions import SpnegoError


def _message_test(client, server):
    # Client wrap
    plaintext = os.urandom(32)

    c_wrap_result = client.wrap(plaintext)

    assert isinstance(c_wrap_result, WrapResult)
    assert c_wrap_result.encrypted
    assert c_wrap_result.data != plaintext

    # Server unwrap
    s_unwrap_result = server.unwrap(c_wrap_result.data)

    assert isinstance(s_unwrap_result, UnwrapResult)
    assert s_unwrap_result.data == plaintext
    assert s_unwrap_result.encrypted
    assert s_unwrap_result.qop == 0

    # Server wrap
    plaintext = os.urandom(17)

    s_wrap_result = server.wrap(plaintext)

    assert isinstance(s_wrap_result, WrapResult)
    assert s_wrap_result.encrypted
    assert s_wrap_result.data != plaintext

    # Client unwrap
    c_unwrap_result = client.unwrap(s_wrap_result.data)

    assert isinstance(c_unwrap_result, UnwrapResult)
    assert c_unwrap_result.data == plaintext
    assert c_unwrap_result.encrypted
    assert c_unwrap_result.qop == 0

    # CredSSP doesnt' have signature methods
    if hasattr(client, 'client_credential'):
        return

    # Client sign, server verify
    plaintext = os.urandom(3)

    c_sig = client.sign(plaintext)
    server.verify(plaintext, c_sig)

    # Server sign, client verify
    plaintext = os.urandom(9)

    s_sig = server.sign(plaintext)
    client.verify(plaintext, s_sig)

    # Can only continue if we are not testing Kerberos, or we are testing Kerberos and GSSAPI is available.
    if client.negotiated_protocol == 'kerberos' and not client.iov_available():
        return

    plaintext = os.urandom(16)
    c_winrm_result = client.wrap_winrm(plaintext)
    assert isinstance(c_winrm_result, WinRMWrapResult)
    assert isinstance(c_winrm_result.header, bytes)
    assert isinstance(c_winrm_result.data, bytes)
    assert isinstance(c_winrm_result.padding_length, int)

    s_winrm_result = server.unwrap_winrm(c_winrm_result.header, c_winrm_result.data)
    assert s_winrm_result == plaintext

    plaintext = os.urandom(16)
    s_winrm_result = server.wrap_winrm(plaintext)
    assert isinstance(s_winrm_result, WinRMWrapResult)
    assert isinstance(s_winrm_result.header, bytes)
    assert isinstance(s_winrm_result.data, bytes)
    assert isinstance(s_winrm_result.padding_length, int)

    c_winrm_result = client.unwrap_winrm(s_winrm_result.header, s_winrm_result.data)
    assert c_winrm_result == plaintext

    # Can only continue if using Kerberos auth and IOV is available
    if client.negotiated_protocol == 'ntlm' or not client.iov_available():
        return

    plaintext = os.urandom(16)
    c_iov_res = client.wrap_iov([spnego.iov.BufferType.header, plaintext, spnego.iov.BufferType.padding])
    assert isinstance(c_iov_res, IOVWrapResult)
    assert c_iov_res.encrypted
    assert len(c_iov_res.buffers) == 3
    assert c_iov_res.buffers[1].data != plaintext

    s_iov_res = server.unwrap_iov(c_iov_res.buffers)
    assert isinstance(s_iov_res, IOVUnwrapResult)
    assert s_iov_res.encrypted
    assert s_iov_res.qop == 0
    assert len(s_iov_res.buffers) == 3
    assert s_iov_res.buffers[1].data == plaintext

    plaintext = os.urandom(16)
    s_iov_res = server.wrap_iov([spnego.iov.BufferType.header, plaintext, spnego.iov.BufferType.padding])
    assert isinstance(s_iov_res, IOVWrapResult)
    assert s_iov_res.encrypted
    assert len(s_iov_res.buffers) == 3
    assert s_iov_res.buffers[1].data != plaintext

    c_iov_res = client.unwrap_iov(s_iov_res.buffers)
    assert isinstance(c_iov_res, IOVUnwrapResult)
    assert c_iov_res.encrypted
    assert c_iov_res.qop == 0
    assert len(c_iov_res.buffers) == 3
    assert c_iov_res.buffers[1].data == plaintext


def _ntlm_test(client, server, test_session_key=True):
    assert not client.complete
    assert not server.complete

    # Build negotiate msg
    negotiate = client.step()

    assert isinstance(negotiate, bytes)
    assert not client.complete
    assert not server.complete

    # Process negotiate msg
    challenge = server.step(negotiate)

    assert isinstance(challenge, bytes)
    assert not client.complete
    assert not server.complete

    # Process challenge and build authenticate
    authenticate = client.step(challenge)

    assert isinstance(authenticate, bytes)
    if test_session_key:
        assert isinstance(client.session_key, bytes)

    assert client.complete
    assert not server.complete

    # Process authenticate
    auth_response = server.step(authenticate)

    assert auth_response is None
    if test_session_key:
        assert isinstance(client.session_key, bytes)
        assert isinstance(server.session_key, bytes)

    assert client.complete
    assert server.complete

    assert client.negotiated_protocol == 'ntlm'
    assert server.negotiated_protocol == 'ntlm'


def test_invalid_protocol():
    expected = "Invalid protocol specified 'fake', must be kerberos, negotiate, or ntlm"

    with pytest.raises(ValueError, match=expected):
        spnego.client(None, None, protocol='fake')

    with pytest.raises(ValueError, match=expected):
        spnego.server(protocol='fake')


def test_protocol_not_supported():
    with pytest.raises(ValueError, match="Protocol kerberos is not available"):
        spnego.client(None, None, protocol='kerberos', options=spnego.NegotiateOptions.use_ntlm)


# Negotiate scenarios

def test_negotiate_with_kerberos(kerb_cred):
    if kerb_cred.provider == "heimdal":
        pytest.skip("Environment problem with Heimdal - skip")

    c = spnego.client(kerb_cred.user_princ, None, hostname=socket.getfqdn(),
                      options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    token1 = c.step()
    assert isinstance(token1, bytes)

    token2 = s.step(token1)
    assert isinstance(token2, bytes)

    token3 = c.step(token2)
    assert token3 is None

    # Make sure it reports the right protocol
    assert c.negotiated_protocol == 'kerberos'
    assert s.negotiated_protocol == 'kerberos'

    assert isinstance(c.session_key, bytes)
    assert isinstance(s.session_key, bytes)
    assert c.session_key == s.session_key

    assert c.client_principal is None
    assert s.client_principal == kerb_cred.user_princ

    assert c.context_attr & spnego.ContextReq.mutual_auth
    assert s.context_attr & spnego.ContextReq.mutual_auth

    _message_test(c, s)


@pytest.mark.parametrize('client_opt, server_opt', [
    (spnego.NegotiateOptions.use_negotiate, spnego.NegotiateOptions.use_negotiate),
    (spnego.NegotiateOptions.use_gssapi, spnego.NegotiateOptions.use_negotiate),
    (spnego.NegotiateOptions.use_negotiate, spnego.NegotiateOptions.use_gssapi),
    # Cannot seem to force SSPI to wrap NTLM solely in SPNEGO, skip this test for now.
    # (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_negotiate),
    (spnego.NegotiateOptions.use_negotiate, spnego.NegotiateOptions.use_sspi),
])
def test_negotiate_through_python_ntlm(client_opt, server_opt, ntlm_cred, monkeypatch):
    if client_opt & spnego.NegotiateOptions.use_negotiate and server_opt & spnego.NegotiateOptions.use_negotiate:
        # Make sure we pretend that the system libraries aren't available
        def available_protocols(*args, **kwargs):
            return []

        monkeypatch.setattr(spnego._gss, '_available_protocols', available_protocols)
        monkeypatch.setattr(spnego._sspi, '_available_protocols', available_protocols)

    elif client_opt & spnego.NegotiateOptions.use_gssapi or server_opt & spnego.NegotiateOptions.use_gssapi:
        if 'ntlm' not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through GSSAPI')

    elif client_opt & spnego.NegotiateOptions.use_sspi or server_opt & spnego.NegotiateOptions.use_sspi:
        if 'ntlm' not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through SSPI')

    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol='negotiate', options=client_opt,
                      context_req=spnego.ContextReq.delegate | spnego.ContextReq.default)
    s = spnego.server(protocol='negotiate', options=server_opt)

    assert not c.complete
    assert not s.complete

    negotiate = c.step()

    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)

    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)

    assert isinstance(authenticate, bytes)
    assert not c.complete
    assert not s.complete

    mech_list_mic = s.step(authenticate)

    assert isinstance(mech_list_mic, bytes)
    assert not c.complete
    assert s.complete

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    mech_list_resp = c.step(mech_list_mic)

    assert mech_list_resp is None
    assert c.complete
    assert s.complete
    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    _message_test(c, s)


def test_negotiate_with_raw_ntlm(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol='ntlm')
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    negotiate = c.step()
    assert negotiate.startswith(b"NTLMSSP\x00\x01")
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge.startswith(b"NTLMSSP\x00\x02")
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert authenticate.startswith(b"NTLMSSP\x00\x03")
    assert c.complete
    assert not s.complete

    final = s.step(authenticate)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)


def test_negotiate_with_ntlm_and_duplicate_response_token(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(),
                      options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    negotiate = c.step()
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)

    # Set the mechListMIC to the same value as responseToken in the challenge to replicate the bug this is testing
    neg_token_resp = unpack_token(challenge)
    assert isinstance(neg_token_resp, NegTokenResp)
    neg_token_resp.mech_list_mic = neg_token_resp.response_token
    challenge = neg_token_resp.pack()

    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert not c.complete
    assert not s.complete

    mech_list = s.step(authenticate)
    assert not c.complete
    assert s.complete

    final = c.step(mech_list)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)


# NTLM scenarios

@pytest.mark.parametrize('lm_compat_level', [None, 0, 1, 2])
def test_ntlm_auth(lm_compat_level, ntlm_cred, monkeypatch):
    if lm_compat_level is not None:
        monkeypatch.setenv('LM_COMPAT_LEVEL', str(lm_compat_level))

    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)
    s = spnego.server(protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.parametrize('client_opt, server_opt', [
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi),
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_ntlm),
    # Cannot test with gssapi as the existing version has a bug with this scenario.
])
def test_sspi_ntlm_auth_no_sign_or_seal(client_opt, server_opt, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi or server_opt & spnego.NegotiateOptions.use_gssapi:
        if 'ntlm' not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through GSSAPI')

    elif client_opt & spnego.NegotiateOptions.use_sspi or server_opt & spnego.NegotiateOptions.use_sspi:
        if 'ntlm' not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through SSPI')

    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), options=client_opt, protocol='ntlm',
                      context_req=0)
    s = spnego.server(options=server_opt, protocol='ntlm', context_req=0)

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    # Client sign, server verify
    plaintext = os.urandom(3)

    c_sig = c.sign(plaintext)
    s.verify(plaintext, c_sig)

    # Server sign, client verify
    plaintext = os.urandom(9)

    s_sig = s.sign(plaintext)
    c.verify(plaintext, s_sig)


@pytest.mark.skipif('ntlm' not in spnego._gss.GSSAPIProxy.available_protocols(),
                    reason='Test requires NTLM to be available through GSSAPI')
@pytest.mark.parametrize('client_opt, server_opt, cbt', [
    (spnego.NegotiateOptions.use_gssapi, spnego.NegotiateOptions.use_gssapi, False),
    (spnego.NegotiateOptions.use_gssapi, spnego.NegotiateOptions.use_gssapi, True),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_gssapi, False),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_gssapi, True),
    (spnego.NegotiateOptions.use_gssapi, spnego.NegotiateOptions.use_ntlm, False),
    (spnego.NegotiateOptions.use_gssapi, spnego.NegotiateOptions.use_ntlm, True),
])
def test_gssapi_ntlm_auth(client_opt, server_opt, ntlm_cred, cbt):
    # Build the initial context and assert the defaults.
    kwargs = {
        'protocol': 'ntlm',
    }
    if cbt:
        kwargs['channel_bindings'] = spnego.channel_bindings.GssChannelBindings(application_data=b'test_data:\x00\x01')

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=client_opt, **kwargs)
    s = spnego.server(options=server_opt, **kwargs)

    # gss-ntlmssp version on CI may be too old to test the session key
    test_session_key = 'ntlm' in spnego._gss.GSSAPIProxy.available_protocols(spnego.NegotiateOptions.session_key)
    _ntlm_test(c, s, test_session_key=test_session_key)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.skipif('ntlm' not in spnego._gss.GSSAPIProxy.available_protocols(),
                    reason='Test requires NTLM to be available through GSSAPI')
@pytest.mark.parametrize('lm_compat_level', [0, 1, 2, 3])
def test_gssapi_ntlm_lm_compat(lm_compat_level, ntlm_cred, monkeypatch):
    monkeypatch.setenv('LM_COMPAT_LEVEL', str(lm_compat_level))
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol='ntlm',
                      options=spnego.NegotiateOptions.use_ntlm)
    s = spnego.server(options=spnego.NegotiateOptions.use_gssapi, protocol='ntlm')

    # gss-ntlmssp version on CI may be too old to test the session key
    test_session_key = 'ntlm' in spnego._gss.GSSAPIProxy.available_protocols(spnego.NegotiateOptions.session_key)
    _ntlm_test(c, s, test_session_key=test_session_key)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.skipif('ntlm' not in spnego._sspi.SSPIProxy.available_protocols(),
                    reason='Test requires NTLM to be available through SSPI')
@pytest.mark.parametrize('client_opt, server_opt, cbt', [
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi, False),
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi, True),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi, False),
    (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi, True),
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, False),
    (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, True),
])
def test_sspi_ntlm_auth(client_opt, server_opt, cbt, ntlm_cred):
    # Build the initial context and assert the defaults.
    kwargs = {
        'protocol': 'ntlm',
    }
    if cbt:
        kwargs['channel_bindings'] = spnego.channel_bindings.GssChannelBindings(application_data=b'test_data:\x00\x01')
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), options=client_opt, **kwargs)
    s = spnego.server(options=server_opt, **kwargs)

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.skipif('ntlm' not in spnego._sspi.SSPIProxy.available_protocols(),
                    reason='Test requires NTLM to be available through SSPI')
@pytest.mark.parametrize('lm_compat_level', [1, 2, 3])
def test_sspi_ntlm_lm_compat(lm_compat_level, ntlm_cred, monkeypatch):
    monkeypatch.setenv('LM_COMPAT_LEVEL', str(lm_compat_level))
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol='ntlm',
                      options=spnego.NegotiateOptions.use_ntlm)
    s = spnego.server(options=spnego.NegotiateOptions.use_sspi, protocol='ntlm')

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


def test_ntlm_with_explicit_ntlm_hash(ntlm_cred):
    ntlm_hashes = f"{lmowfv1(ntlm_cred[1]).hex()}:{ntowfv1(ntlm_cred[1]).hex()}"
    c = spnego.client(ntlm_cred[0], ntlm_hashes,
                      hostname=socket.gethostname(), options=0, protocol='ntlm')
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol='ntlm')

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


# Kerberos scenarios

@pytest.mark.parametrize('explicit_user', [False, True])
def test_gssapi_kerberos_auth(explicit_user, kerb_cred):
    if kerb_cred.provider == "heimdal":
        pytest.skip("Environment problem with Heimdal - skip")

    username = None
    if explicit_user:
        username = kerb_cred.user_princ

    c = spnego.client(username, None, hostname=socket.getfqdn(), protocol='kerberos',
                      options=spnego.NegotiateOptions.use_gssapi)
    s = spnego.server(options=spnego.NegotiateOptions.use_gssapi, protocol='kerberos')

    assert not c.complete
    assert not s.complete
    assert s.negotiated_protocol is None

    with pytest.raises(SpnegoError, match="Retrieving session key"):
        _ = c.session_key

    with pytest.raises(SpnegoError, match="Retrieving session key"):
        _ = s.session_key

    token1 = c.step()
    assert isinstance(token1, bytes)
    assert not c.complete
    assert not s.complete
    assert s.negotiated_protocol is None

    token2 = s.step(token1)
    assert isinstance(token2, bytes)
    assert not c.complete
    assert s.complete
    assert s.negotiated_protocol == 'kerberos'

    token3 = c.step(token2)
    assert token3 is None
    assert c.complete
    assert s.complete
    assert isinstance(c.session_key, bytes)
    assert isinstance(s.session_key, bytes)
    assert c.session_key == s.session_key

    assert c.client_principal is None
    assert s.client_principal == kerb_cred.user_princ

    _message_test(c, s)


@pytest.mark.parametrize('acquire_cred_from', [False, True])
def test_gssapi_kerberos_auth_explicit_cred(acquire_cred_from, kerb_cred, monkeypatch):
    if kerb_cred.provider == "heimdal":
        pytest.skip("Environment problem with Heimdal - skip")

    if not acquire_cred_from:
        monkeypatch.delattr("gssapi.raw.acquire_cred_from")

    context_req = spnego.ContextReq.default | spnego.ContextReq.delegate
    c = spnego.client(kerb_cred.user_princ, kerb_cred.password('user'), hostname=socket.getfqdn(), protocol='kerberos',
                      options=spnego.NegotiateOptions.use_gssapi, context_req=context_req)
    s = spnego.server(options=spnego.NegotiateOptions.use_gssapi, protocol='kerberos')

    assert not c.complete
    assert not s.complete
    assert s.negotiated_protocol is None

    with pytest.raises(SpnegoError, match="Retrieving session key"):
        _ = c.session_key

    with pytest.raises(SpnegoError, match="Retrieving session key"):
        _ = s.session_key

    token1 = c.step()
    assert isinstance(token1, bytes)
    assert not c.complete
    assert not s.complete
    assert s.negotiated_protocol is None

    token2 = s.step(token1)
    assert isinstance(token2, bytes)
    assert not c.complete
    assert s.complete
    assert s.negotiated_protocol == 'kerberos'

    token3 = c.step(token2)
    assert token3 is None
    assert c.complete
    assert s.complete
    assert isinstance(c.session_key, bytes)
    assert isinstance(s.session_key, bytes)
    assert c.session_key == s.session_key

    assert c.client_principal is None
    assert s.client_principal == kerb_cred.user_princ

    assert c.context_attr & spnego.ContextReq.delegate
    assert s.context_attr & spnego.ContextReq.delegate

    _message_test(c, s)


# CredSSP scenarios

@pytest.mark.parametrize('options, restrict_tlsv12, version', [
    (spnego.NegotiateOptions.use_negotiate, False, None),
    (spnego.NegotiateOptions.use_negotiate, False, 2),
    (spnego.NegotiateOptions.use_negotiate, True, None),
    # Using NTLM directly results in a slightly separate behaviour for the pub key.
    (spnego.NegotiateOptions.use_ntlm, False, None),
    (spnego.NegotiateOptions.use_ntlm, False, 5),
    (spnego.NegotiateOptions.use_ntlm, True, None),
])
def test_credssp_ntlm_creds(options, restrict_tlsv12, version, ntlm_cred, monkeypatch, tmp_path):
    context_kwargs = {}
    if restrict_tlsv12:
        credssp_context = spnego.tls.default_tls_context()

        try:
            credssp_context.context.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            credssp_context.context.options |= ssl.Options.OP_NO_TLSv1_3

        cert_pem, key_pem, pub_key = spnego.tls.generate_tls_certificate()
        with open(tmp_path / "ca.pem", mode="wb") as fd:
            fd.write(cert_pem)
            fd.write(key_pem)

        credssp_context.context.load_cert_chain(tmp_path / "ca.pem")
        credssp_context.public_key = pub_key
        context_kwargs["credssp_tls_context"] = credssp_context

    if version:
        monkeypatch.setattr(spnego._credssp, '_CREDSSP_VERSION', version)

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol='credssp', options=options)
    s = spnego.server(protocol='credssp', options=options, **context_kwargs)

    assert c.client_principal is None
    assert c.client_credential is None
    assert c.negotiated_protocol is None

    # The TLS handshake can differ based on the protocol selected, keep on looping until we see the auth_context set up
    # For NTLM the auth context will be present after the first exchange of NTLM tokens.
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert not c.complete
    assert not s.complete

    server_pub_key = s.step(ntlm3_pub_key)
    assert not c.complete
    assert not s.complete

    credential = c.step(server_pub_key)
    assert c.complete
    assert not s.complete

    final_token = s.step(credential)
    assert final_token is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    domain, username = ntlm_cred[0].split('\\')
    assert s.client_credential.username == username
    assert s.client_credential.domain_name == domain
    assert s.client_credential.password == ntlm_cred[1]

    _message_test(c, s)

    plaintext = os.urandom(16)
    c_winrm_result = c.wrap_winrm(plaintext)
    assert isinstance(c_winrm_result, WinRMWrapResult)
    assert isinstance(c_winrm_result.header, bytes)
    assert isinstance(c_winrm_result.data, bytes)
    assert isinstance(c_winrm_result.padding_length, int)

    s_winrm_result = s.unwrap_winrm(c_winrm_result.header, c_winrm_result.data)
    assert s_winrm_result == plaintext

    plaintext = os.urandom(16)
    s_winrm_result = s.wrap_winrm(plaintext)
    assert isinstance(s_winrm_result, WinRMWrapResult)
    assert isinstance(s_winrm_result.header, bytes)
    assert isinstance(s_winrm_result.data, bytes)
    assert isinstance(s_winrm_result.padding_length, int)

    c_winrm_result = c.unwrap_winrm(s_winrm_result.header, s_winrm_result.data)
    assert c_winrm_result == plaintext


@pytest.mark.parametrize('restrict_tlsv12', [False, True])
def test_credssp_kerberos_creds(restrict_tlsv12, kerb_cred):
    if kerb_cred.provider == "heimdal":
        pytest.skip("Environment problem with Heimdal - skip")

    c_kerb_context = spnego.client(kerb_cred.user_princ, None, hostname=socket.getfqdn(), protocol='kerberos')
    s_kerb_context = spnego.server(protocol="kerberos")

    client_kwargs = {}
    if restrict_tlsv12:
        tls_context = spnego.tls.default_tls_context()

        try:
            tls_context.context.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            tls_context.context.options |= ssl.Options.OP_NO_TLSv1_3

        client_kwargs["credssp_tls_context"] = tls_context

    c = spnego.client(kerb_cred.user_princ, kerb_cred.password('user'), protocol='credssp',
                      credssp_negotiate_context=c_kerb_context, **client_kwargs)
    s = spnego.server(protocol='credssp', credssp_negotiate_context=s_kerb_context)

    server_token = None
    while not c_kerb_context.complete:
        client_token = c.step(server_token)
        assert not c.complete
        assert not s.complete

        server_token = s.step(client_token)
        assert not c.complete
        assert not s.complete

    assert s_kerb_context.complete

    credential = c.step(server_token)
    assert c.complete
    assert not s.complete

    final_token = s.step(credential)
    assert final_token is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == 'kerberos'
    assert s.negotiated_protocol == 'kerberos'
    assert c_kerb_context.negotiated_protocol == 'kerberos'
    assert s_kerb_context.negotiated_protocol == 'kerberos'

    assert s.client_principal == kerb_cred.user_princ
    assert s.client_credential.username == kerb_cred.user_princ
    assert s.client_credential.password == kerb_cred.password('user')

    _message_test(c, s)

    plaintext = os.urandom(16)
    c_winrm_result = c.wrap_winrm(plaintext)
    assert isinstance(c_winrm_result, WinRMWrapResult)
    assert isinstance(c_winrm_result.header, bytes)
    assert isinstance(c_winrm_result.data, bytes)
    assert isinstance(c_winrm_result.padding_length, int)

    s_winrm_result = s.unwrap_winrm(c_winrm_result.header, c_winrm_result.data)
    assert s_winrm_result == plaintext

    plaintext = os.urandom(16)
    s_winrm_result = s.wrap_winrm(plaintext)
    assert isinstance(s_winrm_result, WinRMWrapResult)
    assert isinstance(s_winrm_result.header, bytes)
    assert isinstance(s_winrm_result.data, bytes)
    assert isinstance(s_winrm_result.padding_length, int)

    c_winrm_result = c.unwrap_winrm(s_winrm_result.header, s_winrm_result.data)
    assert c_winrm_result == plaintext
