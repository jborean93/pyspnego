# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import os
import socket

import pytest

import spnego
import spnego.channel_bindings
import spnego.gss
import spnego.sspi

from spnego._context import (
    WrapResult,
    UnwrapResult,
)


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

    # Client sign, server verify
    plaintext = os.urandom(3)

    c_sig = client.sign(plaintext)
    server.verify(plaintext, c_sig)

    # Server sign, client verify
    plaintext = os.urandom(9)

    s_sig = server.sign(plaintext)
    client.verify(plaintext, s_sig)


def test_invalid_protocol():
    expected = "Invalid protocol specified 'fake', must be kerberos, negotiate, or ntlm"

    with pytest.raises(ValueError, match=expected):
        spnego.client(None, None, protocol='fake')

    with pytest.raises(ValueError, match=expected):
        spnego.server(None, None, protocol='fake')


def test_protocol_not_supported():
    with pytest.raises(ValueError, match="Protocol kerberos is not available"):
        spnego.client(None, None, protocol='kerberos', options=spnego.NegotiateOptions.use_ntlm)


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

        monkeypatch.setattr(spnego.gss, '_available_protocols', available_protocols)
        monkeypatch.setattr(spnego.sspi, '_available_protocols', available_protocols)

    elif client_opt & spnego.NegotiateOptions.use_gssapi or server_opt & spnego.NegotiateOptions.use_gssapi:
        if 'ntlm' not in spnego.gss.GSSAPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through GSSAPI')

    elif client_opt & spnego.NegotiateOptions.use_sspi or server_opt & spnego.NegotiateOptions.use_sspi:
        if 'ntlm' not in spnego.sspi.SSPIProxy.available_protocols():
            pytest.skip('Test requires NTLM to be available through SSPI')

    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol='negotiate', options=client_opt)
    s = spnego.server(None, None, protocol='negotiate', options=server_opt)

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

    mech_list_resp = c.step(mech_list_mic)

    assert mech_list_resp is None
    assert c.complete
    assert s.complete
    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    _message_test(c, s)


def test_ntlm_auth(ntlm_cred):
    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)
    s = spnego.server(None, None, protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)

    assert not c.complete
    assert not s.complete

    # Build negotiate msg
    negotiate = c.step()

    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete

    # Process negotiate msg
    challenge = s.step(negotiate)

    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    # Process challenge and build authenticate
    authenticate = c.step(challenge)

    assert isinstance(authenticate, bytes)
    assert isinstance(c.session_key, bytes)
    assert c.complete
    assert not s.complete

    # Process authenticate
    auth_response = s.step(authenticate)

    assert auth_response is None
    assert isinstance(c.session_key, bytes)
    assert isinstance(s.session_key, bytes)
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    # Client wrap
    _message_test(c, s)


@pytest.mark.skipif('ntlm' not in spnego.gss.GSSAPIProxy.available_protocols(),
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
    s = spnego.server(None, None, options=server_opt, **kwargs)

    assert not c.complete
    assert not s.complete

    # Build negotiate msg
    negotiate = c.step()

    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete

    # Process negotiate msg
    challenge = s.step(negotiate)

    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    # Process challenge and build authenticate
    authenticate = c.step(challenge)

    assert isinstance(authenticate, bytes)
    assert c.complete
    assert not s.complete

    # Process authenticate
    auth_response = s.step(authenticate)

    assert auth_response is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    # Client wrap
    _message_test(c, s)


@pytest.mark.skipif('ntlm' not in spnego.sspi.SSPIProxy.available_protocols(),
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
    s = spnego.server(None, None, options=server_opt, **kwargs)

    assert not c.complete
    assert not s.complete

    # Build negotiate msg
    negotiate = c.step()

    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete

    # Process negotiate msg
    challenge = s.step(negotiate)

    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    # Process challenge and build authenticate
    authenticate = c.step(challenge)

    assert isinstance(authenticate, bytes)
    assert isinstance(c.session_key, bytes)
    assert c.complete
    assert not s.complete

    # Process authenticate
    auth_response = s.step(authenticate)

    assert auth_response is None
    assert isinstance(c.session_key, bytes)
    assert isinstance(s.session_key, bytes)
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == 'ntlm'
    assert s.negotiated_protocol == 'ntlm'

    # Client wrap
    _message_test(c, s)
