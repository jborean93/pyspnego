# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import socket
import ssl
import typing

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
from spnego._credssp_structures import TSPasswordCreds
from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1
from spnego._spnego import NegTokenResp, unpack_token
from spnego.exceptions import (
    InvalidCredentialError,
    InvalidTokenError,
    NoCredentialError,
    OperationNotAvailableError,
    SpnegoError,
)

from .conftest import KerberosRealm


def _message_test(client: spnego.ContextProxy, server: spnego.ContextProxy) -> None:
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
    if isinstance(client, spnego._credssp.CredSSPProxy):
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
    if client.negotiated_protocol == "kerberos" and not client.iov_available():
        return

    plaintext = os.urandom(16)
    c_winrm_wrap_result = client.wrap_winrm(plaintext)
    assert isinstance(c_winrm_wrap_result, WinRMWrapResult)
    assert isinstance(c_winrm_wrap_result.header, bytes)
    assert isinstance(c_winrm_wrap_result.data, bytes)
    assert isinstance(c_winrm_wrap_result.padding_length, int)

    s_winrm_unwrap_result = server.unwrap_winrm(c_winrm_wrap_result.header, c_winrm_wrap_result.data)
    assert s_winrm_unwrap_result == plaintext

    plaintext = os.urandom(16)
    s_winrm_wrap_result = server.wrap_winrm(plaintext)
    assert isinstance(s_winrm_wrap_result, WinRMWrapResult)
    assert isinstance(s_winrm_wrap_result.header, bytes)
    assert isinstance(s_winrm_wrap_result.data, bytes)
    assert isinstance(s_winrm_wrap_result.padding_length, int)

    c_winrm_unwrap_result = client.unwrap_winrm(s_winrm_wrap_result.header, s_winrm_wrap_result.data)
    assert c_winrm_unwrap_result == plaintext

    # Can only continue if using Kerberos auth and IOV is available
    if client.negotiated_protocol == "ntlm" or not client.iov_available():
        return

    plaintext = os.urandom(16)
    c_iov_wrap_res = client.wrap_iov([spnego.iov.BufferType.header, plaintext, spnego.iov.BufferType.padding])
    assert isinstance(c_iov_wrap_res, IOVWrapResult)
    assert c_iov_wrap_res.encrypted
    assert len(c_iov_wrap_res.buffers) == 3
    assert c_iov_wrap_res.buffers[1].data != plaintext

    s_iov_unwrap_res = server.unwrap_iov(c_iov_wrap_res.buffers)
    assert isinstance(s_iov_unwrap_res, IOVUnwrapResult)
    assert s_iov_unwrap_res.encrypted
    assert s_iov_unwrap_res.qop == 0
    assert len(s_iov_unwrap_res.buffers) == 3
    assert s_iov_unwrap_res.buffers[1].data == plaintext

    plaintext = os.urandom(16)
    s_iov_wrap_res = server.wrap_iov([spnego.iov.BufferType.header, plaintext, spnego.iov.BufferType.padding])
    assert isinstance(s_iov_wrap_res, IOVWrapResult)
    assert s_iov_wrap_res.encrypted
    assert len(s_iov_wrap_res.buffers) == 3
    assert s_iov_wrap_res.buffers[1].data != plaintext

    c_iov_unwrap_res = client.unwrap_iov(s_iov_wrap_res.buffers)
    assert isinstance(c_iov_unwrap_res, IOVUnwrapResult)
    assert c_iov_unwrap_res.encrypted
    assert c_iov_unwrap_res.qop == 0
    assert len(c_iov_unwrap_res.buffers) == 3
    assert c_iov_unwrap_res.buffers[1].data == plaintext


def _ntlm_test(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
    test_session_key: bool = True,
    channel_bindings: typing.Optional[spnego.channel_bindings.GssChannelBindings] = None,
) -> None:
    assert not client.complete
    assert not server.complete

    # Build negotiate msg
    negotiate = client.step(channel_bindings=channel_bindings)

    assert isinstance(negotiate, bytes)
    assert not client.complete
    assert not server.complete

    # Process negotiate msg
    challenge = server.step(negotiate, channel_bindings=channel_bindings)

    assert isinstance(challenge, bytes)
    assert not client.complete
    assert not server.complete

    # Process challenge and build authenticate
    authenticate = client.step(challenge, channel_bindings=channel_bindings)

    assert isinstance(authenticate, bytes)
    if test_session_key:
        assert isinstance(client.session_key, bytes)

    assert client.complete
    assert not server.complete

    # Process authenticate
    auth_response = server.step(authenticate, channel_bindings=channel_bindings)

    assert auth_response is None
    if test_session_key:
        assert isinstance(client.session_key, bytes)
        assert isinstance(server.session_key, bytes)

    assert client.complete
    assert server.complete

    assert client.negotiated_protocol == "ntlm"
    assert server.negotiated_protocol == "ntlm"


def test_invalid_protocol():
    expected = "Invalid protocol specified 'fake', must be kerberos, negotiate, or ntlm"

    with pytest.raises(ValueError, match=expected):
        spnego.client(None, None, protocol="fake")

    with pytest.raises(ValueError, match=expected):
        spnego.server(protocol="fake")


def test_protocol_not_supported():
    with pytest.raises(ValueError, match="Protocol kerberos is not available"):
        spnego.client(None, None, protocol="kerberos", options=spnego.NegotiateOptions.use_ntlm)


def test_no_valid_credential_available_single_available_protocol():
    credentials: typing.List[spnego.Credential] = [
        spnego.KerberosCCache("FILE:test"),
        spnego.KerberosKeytab("principal", "keytab"),
    ]
    with pytest.raises(
        NoCredentialError, match="A credential for ntlm is needed but only found credentials for kerberos"
    ):
        spnego.client(credentials, protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)


def test_no_valid_credential_available_multiple_available_protocol():
    credentials: typing.List[spnego.Credential] = [
        spnego.NTLMHash("username", "lm_hash", "nt_hash"),
        spnego.KerberosKeytab("principal", "keytab"),
    ]
    with pytest.raises(
        NoCredentialError, match="A credential for credssp is needed but only found credentials for kerberos, ntlm"
    ):
        spnego.client(credentials, protocol="credssp")


# Negotiate scenarios


def test_negotiate_with_kerberos(kerb_realm):
    c = kerb_realm.client(kerb_realm.username, protocol="negotiate", options=spnego.NegotiateOptions.use_negotiate)
    s = kerb_realm.server(protocol="negotiate", options=spnego.NegotiateOptions.use_negotiate)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    for client, server in _kerberos_auth_test(c, s, kerb_realm):
        assert client.context_attr & spnego.ContextReq.mutual_auth
        assert server.context_attr & spnego.ContextReq.mutual_auth


def test_negotiate_through_python_ntlm(ntlm_cred):
    # Build the initial context and assert the defaults.
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        protocol="negotiate",
        context_req=spnego.ContextReq.delegate | spnego.ContextReq.default,
        options=spnego.NegotiateOptions.use_negotiate,
    )
    s = spnego.server(protocol="negotiate")

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

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
    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

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
    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    _message_test(c, s)


def test_negotiate_with_raw_ntlm(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="ntlm")
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    negotiate = c.step()
    assert negotiate is not None
    assert negotiate.startswith(b"NTLMSSP\x00\x01")
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge is not None
    assert challenge.startswith(b"NTLMSSP\x00\x02")
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert authenticate is not None
    assert authenticate.startswith(b"NTLMSSP\x00\x03")
    assert c.complete
    assert not s.complete

    final = s.step(authenticate)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    negotiate = c.step()
    assert negotiate is not None
    assert negotiate.startswith(b"NTLMSSP\x00\x01")
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge is not None
    assert challenge.startswith(b"NTLMSSP\x00\x02")
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert authenticate is not None
    assert authenticate.startswith(b"NTLMSSP\x00\x03")
    assert c.complete
    assert not s.complete

    final = s.step(authenticate)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)


def test_negotiate_with_ntlm_hash(ntlm_cred):
    cred = spnego.NTLMHash(username=ntlm_cred[0], nt_hash=ntowfv1(ntlm_cred[1]).hex())
    c = spnego.client(cred, hostname=socket.gethostname())
    s = spnego.server()

    negotiate = c.step()
    assert negotiate is not None
    assert b"NTLMSSP\x00\x01" in negotiate
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge is not None
    assert b"NTLMSSP\x00\x02" in challenge
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert authenticate is not None
    assert b"NTLMSSP\x00\x03" in authenticate
    assert not c.complete
    assert not s.complete

    mic = s.step(authenticate)
    assert mic is not None
    assert not c.complete
    assert s.complete

    final = c.step(mic)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    negotiate = c.step()
    assert negotiate is not None
    assert b"NTLMSSP\x00\x01" in negotiate
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge is not None
    assert b"NTLMSSP\x00\x02" in challenge
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert authenticate is not None
    assert b"NTLMSSP\x00\x03" in authenticate
    assert not c.complete
    assert not s.complete

    mic = s.step(authenticate)
    assert mic is not None
    assert not c.complete
    assert s.complete

    final = c.step(mic)
    assert final is None
    assert c.complete
    assert s.complete

    _message_test(c, s)


def test_negotiate_with_ntlm_and_duplicate_response_token(ntlm_cred):
    c = spnego.client(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), options=spnego.NegotiateOptions.use_negotiate
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    negotiate = c.step()
    assert not c.complete
    assert not s.complete

    challenge = s.step(negotiate)
    assert challenge is not None

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


@pytest.mark.parametrize("lm_compat_level", [None, 0, 1, 2])
def test_ntlm_auth(lm_compat_level, ntlm_cred, monkeypatch):
    if lm_compat_level is not None:
        monkeypatch.setenv("LM_COMPAT_LEVEL", str(lm_compat_level))

    # Build the initial context and assert the defaults.
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    s = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    with pytest.warns(DeprecationWarning, match="username is deprecated"):
        c.username

    with pytest.warns(DeprecationWarning, match="password is deprecated"):
        c.password

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.parametrize(
    "client_opt, server_opt",
    [
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi),
        (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm),
        (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_ntlm),
        # Cannot test with gssapi as the existing version has a bug with this scenario.
    ],
)
def test_sspi_ntlm_auth_no_sign_or_seal(client_opt, server_opt, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi or server_opt & spnego.NegotiateOptions.use_gssapi:
        if "ntlm" not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through GSSAPI")

    elif client_opt & spnego.NegotiateOptions.use_sspi or server_opt & spnego.NegotiateOptions.use_sspi:
        if "ntlm" not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through SSPI")

    # Build the initial context and assert the defaults.
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=client_opt,
        protocol="ntlm",
        context_req=spnego.ContextReq.none,
    )
    s = spnego.server(options=server_opt, protocol="ntlm", context_req=spnego.ContextReq.none)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

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


@pytest.mark.skipif(
    "ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Test requires NTLM to be available through SSPI"
)
@pytest.mark.parametrize(
    "client_opt, server_opt, cbt, cbt_with_step",
    [
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi, False, False),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi, True, False),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_sspi, True, True),
        (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi, False, False),
        (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi, True, False),
        (spnego.NegotiateOptions.use_ntlm, spnego.NegotiateOptions.use_sspi, True, True),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, False, False),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, True, False),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, True, False),
        (spnego.NegotiateOptions.use_sspi, spnego.NegotiateOptions.use_ntlm, True, True),
    ],
)
def test_sspi_ntlm_auth(client_opt, server_opt, cbt, cbt_with_step, ntlm_cred):
    # Build the initial context and assert the defaults.
    step_kwargs: typing.Dict[str, typing.Any] = {}
    client_kwargs: typing.Dict[str, typing.Any] = {}
    server_kwargs: typing.Dict[str, typing.Any] = {}

    if cbt:
        bindings = spnego.channel_bindings.GssChannelBindings(application_data=b"test_data:\x00\x01")
        if cbt_with_step:
            step_kwargs["channel_bindings"] = bindings
            client_kwargs["channel_bindings"] = spnego.channel_bindings.GssChannelBindings(
                application_data=b"test_data:\x00\x02"
            )
            server_kwargs["channel_bindings"] = spnego.channel_bindings.GssChannelBindings(
                application_data=b"test_data:\x00\x03"
            )
        else:
            client_kwargs["channel_bindings"] = bindings
            server_kwargs["channel_bindings"] = bindings

    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=client_opt,
        protocol="ntlm",
        **client_kwargs,
    )
    s = spnego.server(options=server_opt, protocol="ntlm", **server_kwargs)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    _ntlm_test(c, s, **step_kwargs)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    _ntlm_test(c, s, **step_kwargs)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


@pytest.mark.skipif(
    "ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Test requires NTLM to be available through SSPI"
)
@pytest.mark.parametrize("lm_compat_level", [1, 2, 3])
def test_sspi_ntlm_lm_compat(lm_compat_level, ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", str(lm_compat_level))
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_sspi, protocol="ntlm")

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


def test_ntlm_with_explicit_ntlm_hash(ntlm_cred):
    ntlm_hashes = f"{lmowfv1(ntlm_cred[1]).hex()}:{ntowfv1(ntlm_cred[1]).hex()}"
    c = spnego.client(
        ntlm_cred[0], ntlm_hashes, hostname=socket.gethostname(), options=spnego.NegotiateOptions.none, protocol="ntlm"
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()
    _ntlm_test(c, s)

    assert c.client_principal is None
    assert s.client_principal == ntlm_cred[0]

    _message_test(c, s)


def test_ntlm_with_unsupported_credential():
    with pytest.raises(
        InvalidCredentialError, match="Invalid username/credential specified, must be a string or Credential object."
    ):
        spnego.client(123, protocol="ntlm")  # type: ignore[arg-type] # Testing this scenario


# Kerberos scenarios


def _kerberos_exchange(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
    kerb_realm: KerberosRealm,
    step_kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
) -> None:
    """Runs the Kerberos token exchange and checks the established contexts."""
    step_kwargs = step_kwargs or {}

    # SPNEGO only knows the protocol once the first token has been processed.
    initial_protocol = None if server.protocol == "negotiate" else "kerberos"

    assert not client.complete
    assert not server.complete
    assert server.negotiated_protocol == initial_protocol

    token1 = client.step(**step_kwargs)
    assert isinstance(token1, bytes)
    assert not client.complete
    assert not server.complete
    assert server.negotiated_protocol == initial_protocol

    token2 = server.step(token1, **step_kwargs)
    assert isinstance(token2, bytes)
    assert not client.complete
    assert server.complete
    assert server.negotiated_protocol == "kerberos"

    token3 = client.step(token2, **step_kwargs)
    assert token3 is None
    assert client.complete
    assert server.complete
    assert client.negotiated_protocol == "kerberos"
    assert server.negotiated_protocol == "kerberos"

    assert isinstance(client.session_key, bytes)
    assert isinstance(server.session_key, bytes)
    assert client.session_key == server.session_key

    assert client.client_principal is None
    assert server.client_principal == kerb_realm.expected_client_principal


def _kerberos_auth_test(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
    kerb_realm: KerberosRealm,
    step_kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
    message_test: bool = True,
) -> typing.List[typing.Tuple[spnego.ContextProxy, spnego.ContextProxy]]:
    """Authenticates the client to the server with Kerberos.

    Runs the exchange and wraps messages with the contexts unless message_test
    is False, then does the same with a new context from each side to check
    the credentials are reusable. Returns both pairs of contexts so a test can
    check more of their state.
    """
    contexts: typing.List[typing.Tuple[spnego.ContextProxy, spnego.ContextProxy]] = []
    for _ in range(2):
        if contexts:
            client = client.new_context()
            server = server.new_context()

        _kerberos_exchange(client, server, kerb_realm, step_kwargs)
        if message_test:
            _message_test(client, server)
        contexts.append((client, server))

    return contexts


@pytest.mark.parametrize("protocol", ["kerberos", "negotiate"])
@pytest.mark.parametrize("explicit_user", [False, True])
def test_kerberos_auth(protocol, explicit_user, kerb_realm):
    username = kerb_realm.username if explicit_user else None
    c = kerb_realm.client(username, protocol=protocol)
    s = kerb_realm.server(protocol=protocol)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    # The GSSAPI and SSPI proxies fail here, negotiate with GSSAPI may use the
    # Python SPNEGO wrapper which returns an empty key instead.
    if protocol == "kerberos" or kerb_realm.provider == "sspi":
        with pytest.raises(SpnegoError, match="Retrieving session key"):
            _ = c.session_key

        with pytest.raises(SpnegoError, match="Retrieving session key"):
            _ = s.session_key

    _kerberos_auth_test(c, s, kerb_realm)


@pytest.mark.parametrize(
    "protocol, options",
    [
        ("kerberos", spnego.NegotiateOptions.none),
        ("negotiate", spnego.NegotiateOptions.use_negotiate),
    ],
)
@pytest.mark.parametrize("explicit_user", [False, True])
def test_kerberos_auth_no_integrity(protocol, options, explicit_user, kerb_realm):
    username = kerb_realm.username if explicit_user else None
    context_req = spnego.ContextReq.mutual_auth | spnego.ContextReq.sequence_detect | spnego.ContextReq.no_integrity
    c = kerb_realm.client(username, protocol=protocol, options=options, context_req=context_req)
    s = kerb_realm.server(protocol=protocol, options=options)

    # GSSAPI still encrypts without confidentiality being negotiated, SSPI
    # rejects it as unsupported. SSPI Kerberos always provides integrity.
    is_sspi = kerb_realm.provider == "sspi"
    expected_attr = spnego.ContextReq.mutual_auth | spnego.ContextReq.sequence_detect
    if is_sspi:
        expected_attr |= spnego.ContextReq.integrity

    for client, server in _kerberos_auth_test(c, s, kerb_realm, message_test=not is_sspi):
        assert client.context_attr == expected_attr
        assert server.context_attr == expected_attr

        if is_sspi:
            with pytest.raises(OperationNotAvailableError):
                client.wrap(b"data")


@pytest.mark.parametrize("acquire_cred_from", [False, True])
def test_kerberos_auth_explicit_cred(acquire_cred_from, kerb_realm, monkeypatch):
    if not acquire_cred_from:
        # Without acquire_cred_from GSSAPI stores the TGT in a temporary
        # credential cache before acquiring the credential from it.
        gssapi = pytest.importorskip("gssapi")
        monkeypatch.delattr(gssapi.raw, "acquire_cred_from", raising=False)

    context_req = spnego.ContextReq.default | spnego.ContextReq.delegate
    c = kerb_realm.client(kerb_realm.username, kerb_realm.password, context_req=context_req)
    s = kerb_realm.server()

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"

    for client, server in _kerberos_auth_test(c, s, kerb_realm):
        assert client.context_attr & spnego.ContextReq.delegate
        assert server.context_attr & spnego.ContextReq.delegate


@pytest.mark.parametrize("protocol", ["kerberos", "negotiate"])
@pytest.mark.parametrize("set_principal", [False, True])
def test_kerberos_auth_keytab(protocol, set_principal, kerb_realm):
    if set_principal:
        kt = spnego.KerberosKeytab(keytab=kerb_realm.client_keytab, principal=kerb_realm.username)
    elif kerb_realm.provider == "sspi":
        pytest.skip("KerberosKeytab for SSPI requires a principal to be set")
    else:
        kt = spnego.KerberosKeytab(keytab=kerb_realm.client_keytab)

    c = kerb_realm.client(kt, protocol=protocol)
    s = kerb_realm.server(protocol=protocol)

    _kerberos_auth_test(c, s, kerb_realm)


@pytest.mark.parametrize("protocol", ["kerberos", "negotiate"])
@pytest.mark.parametrize("explicit_user", [False, True])
def test_kerberos_auth_ccache(protocol, explicit_user, kerb_realm, kerb_ccache, monkeypatch):
    # Verifies we are actually using our explicit ccache and not the default.
    monkeypatch.setenv("KRB5CCNAME", "missing")

    principal = kerb_realm.username if explicit_user else None
    ccache = spnego.KerberosCCache(ccache=kerb_ccache, principal=principal)

    c = kerb_realm.client(ccache, protocol=protocol)
    s = kerb_realm.server(protocol=protocol)

    _kerberos_auth_test(c, s, kerb_realm)


@pytest.mark.parametrize("protocol", ["kerberos", "negotiate"])
def test_kerberos_auth_credential_cache(protocol, kerb_realm):
    cred = spnego.CredentialCache(username=kerb_realm.username)

    c = kerb_realm.client(cred, protocol=protocol)
    s = kerb_realm.server(protocol=protocol)

    _kerberos_auth_test(c, s, kerb_realm)


@pytest.mark.parametrize("protocol", ["kerberos", "negotiate"])
@pytest.mark.parametrize("with_step", [False, True])
def test_kerberos_auth_channel_bindings(protocol, with_step, kerb_realm):
    cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"test_data:\x00\x01")

    step_kwargs: typing.Dict[str, typing.Any] = {}
    client_kwargs: typing.Dict[str, typing.Any] = {}
    server_kwargs: typing.Dict[str, typing.Any] = {}
    if with_step:
        step_kwargs["channel_bindings"] = cbt

        # Use a fake value to ensure step takes priority.
        client_kwargs["channel_bindings"] = spnego.channel_bindings.GssChannelBindings(
            application_data=b"test_data:\x00\x02"
        )
        server_kwargs["channel_bindings"] = spnego.channel_bindings.GssChannelBindings(
            application_data=b"test_data:\x00\x03"
        )
    else:
        client_kwargs["channel_bindings"] = cbt
        server_kwargs["channel_bindings"] = cbt

    c = kerb_realm.client(kerb_realm.username, kerb_realm.password, protocol=protocol, **client_kwargs)
    s = kerb_realm.server(protocol=protocol, **server_kwargs)

    _kerberos_auth_test(c, s, kerb_realm, step_kwargs=step_kwargs)


# CredSSP scenarios


@pytest.mark.parametrize(
    "options, restrict_tlsv12, version",
    [
        (spnego.NegotiateOptions.use_negotiate, False, None),
        (spnego.NegotiateOptions.use_negotiate, False, 2),
        (spnego.NegotiateOptions.use_negotiate, True, None),
        # Using NTLM directly results in a slightly separate behaviour for the pub key.
        (spnego.NegotiateOptions.use_ntlm, False, None),
        (spnego.NegotiateOptions.use_ntlm, False, 5),
        (spnego.NegotiateOptions.use_ntlm, True, None),
    ],
)
def test_credssp_ntlm_creds(options, restrict_tlsv12, version, ntlm_cred, monkeypatch, tmp_path):
    context_kwargs: typing.Dict[str, typing.Any] = {}
    if restrict_tlsv12:
        credssp_context = spnego.tls.default_tls_context(usage="accept")

        tls_version = getattr(ssl, "TLSVersion", None)
        if hasattr(credssp_context.context, "maximum_version") and tls_version:
            setattr(credssp_context.context, "maximum_version", tls_version.TLSv1_2)

        else:
            credssp_context.context.options |= ssl.Options.OP_NO_TLSv1_3

        cert_pem, key_pem, pub_key = spnego.tls.generate_tls_certificate()
        with open(tmp_path / "ca.pem", mode="wb") as fd:
            fd.write(cert_pem)
            fd.write(key_pem)

        credssp_context.context.load_cert_chain(tmp_path / "ca.pem")
        credssp_context.public_key = pub_key
        context_kwargs["credssp_tls_context"] = credssp_context

    if version:
        monkeypatch.setattr(spnego._credssp, "_CREDSSP_VERSION", version)
    else:
        version = spnego._credssp._CREDSSP_VERSION

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options)
    s = spnego.server(protocol="credssp", options=options, **context_kwargs)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"
    assert c.get_extra_info("client_credential") is None
    assert isinstance(c.get_extra_info("sslcontext"), ssl.SSLContext)
    assert isinstance(c.get_extra_info("ssl_object"), ssl.SSLObject)
    assert c.get_extra_info("auth_stage") == "TLS Handshake"

    assert s.get_extra_info("client_credential") is None
    assert isinstance(s.get_extra_info("sslcontext"), ssl.SSLContext)
    assert isinstance(s.get_extra_info("ssl_object"), ssl.SSLObject)
    assert s.get_extra_info("auth_stage") == "TLS Handshake"

    assert c.client_principal is None
    assert c.get_extra_info("client_credential") is None
    assert c.negotiated_protocol is None

    server_tls_token = None
    while c.get_extra_info("auth_stage") == "TLS Handshake":
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert c.get_extra_info("auth_stage") == "Public key exchange"
    assert s.get_extra_info("auth_stage").startswith("Authentication")
    assert not c.complete
    assert not s.complete

    server_pub_key = s.step(ntlm3_pub_key)
    assert c.get_extra_info("auth_stage") == "Public key exchange"
    assert s.get_extra_info("auth_stage") == "Public key exchange"
    assert not c.complete
    assert not s.complete

    credential = c.step(server_pub_key)
    assert c.get_extra_info("auth_stage") == "Credential exchange"
    assert s.get_extra_info("auth_stage") == "Public key exchange"
    assert c.complete
    assert not s.complete

    final_token = s.step(credential)
    assert c.get_extra_info("auth_stage") == "Credential exchange"
    assert s.get_extra_info("auth_stage") == "Credential exchange"
    assert final_token is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    domain, username = ntlm_cred[0].split("\\")

    assert c.get_extra_info("client_credential") is None
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == username
    assert client_credential.domain_name == domain
    assert client_credential.password == ntlm_cred[1]

    assert c.get_extra_info("protocol_version") == version
    assert s.get_extra_info("protocol_version") == version

    assert isinstance(c.query_message_sizes().header, int)
    assert isinstance(s.query_message_sizes().header, int)

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

    c = c.new_context()
    s = s.new_context()

    server_tls_token = None
    while c.get_extra_info("auth_stage") == "TLS Handshake":
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert c.get_extra_info("auth_stage") == "Public key exchange"
    assert s.get_extra_info("auth_stage").startswith("Authentication")
    assert not c.complete
    assert not s.complete

    server_pub_key = s.step(ntlm3_pub_key)
    assert c.get_extra_info("auth_stage") == "Public key exchange"
    assert s.get_extra_info("auth_stage") == "Public key exchange"
    assert not c.complete
    assert not s.complete

    credential = c.step(server_pub_key)
    assert c.get_extra_info("auth_stage") == "Credential exchange"
    assert s.get_extra_info("auth_stage") == "Public key exchange"
    assert c.complete
    assert not s.complete

    final_token = s.step(credential)
    assert c.get_extra_info("auth_stage") == "Credential exchange"
    assert s.get_extra_info("auth_stage") == "Credential exchange"
    assert final_token is None
    assert c.complete
    assert s.complete

    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    domain, username = ntlm_cred[0].split("\\")

    assert c.get_extra_info("client_credential") is None
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == username
    assert client_credential.domain_name == domain
    assert client_credential.password == ntlm_cred[1]

    assert c.get_extra_info("protocol_version") == version
    assert s.get_extra_info("protocol_version") == version

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


@pytest.mark.parametrize("restrict_tlsv12", [False, True])
def test_credssp_kerberos_creds(restrict_tlsv12, kerb_realm):
    c_kerb_context = kerb_realm.client(kerb_realm.username)
    s_kerb_context = kerb_realm.server()

    client_kwargs: typing.Dict[str, typing.Any] = {}
    if restrict_tlsv12:
        tls_context = spnego.tls.default_tls_context()

        tls_version = getattr(ssl, "TLSVersion", None)
        if hasattr(tls_context.context, "maximum_version") and tls_version:
            setattr(tls_context.context, "maximum_version", tls_version.TLSv1_2)

        else:
            tls_context.context.options |= ssl.Options.OP_NO_TLSv1_3

        client_kwargs["credssp_tls_context"] = tls_context

    c = spnego.client(
        kerb_realm.username,
        kerb_realm.password,
        protocol="credssp",
        credssp_negotiate_context=c_kerb_context,
        **client_kwargs,
    )
    s = spnego.server(protocol="credssp", credssp_negotiate_context=s_kerb_context)

    assert c.get_extra_info("invalid") is None
    assert c.get_extra_info("invalid", "default") == "default"
    assert c.get_extra_info("client_credential") is None
    assert isinstance(c.get_extra_info("sslcontext"), ssl.SSLContext)
    assert isinstance(c.get_extra_info("ssl_object"), ssl.SSLObject)

    assert s.get_extra_info("client_credential") is None
    assert isinstance(s.get_extra_info("sslcontext"), ssl.SSLContext)
    assert isinstance(s.get_extra_info("ssl_object"), ssl.SSLObject)

    server_token = None
    while c.get_extra_info("auth_stage") != "Public key exchange":
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

    assert c.negotiated_protocol == "kerberos"
    assert s.negotiated_protocol == "kerberos"
    assert c_kerb_context.negotiated_protocol == "kerberos"
    assert s_kerb_context.negotiated_protocol == "kerberos"

    assert s.client_principal == kerb_realm.expected_client_principal
    assert c.get_extra_info("client_credential") is None
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == kerb_realm.username
    assert client_credential.password == kerb_realm.password

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

    c = c.new_context()
    s = s.new_context()

    server_token = None
    while c.get_extra_info("auth_stage") != "Public key exchange":
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

    assert c.negotiated_protocol == "kerberos"
    assert s.negotiated_protocol == "kerberos"
    assert c_kerb_context.negotiated_protocol == "kerberos"
    assert s_kerb_context.negotiated_protocol == "kerberos"

    assert s.client_principal == kerb_realm.expected_client_principal
    assert c.get_extra_info("client_credential") is None
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == kerb_realm.username
    assert client_credential.password == kerb_realm.password

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


def test_credssp_multiple_creds(ntlm_cred):
    creds: typing.List[spnego.Credential] = [
        spnego.NTLMHash(username=ntlm_cred[0], nt_hash=ntowfv1(ntlm_cred[1]).hex()),
        spnego.Password(username="delegate", password="password"),
    ]
    c = spnego.client(creds, hostname=socket.gethostname(), protocol="credssp")
    s = spnego.server(protocol="credssp")

    assert c.client_principal is None
    assert c.negotiated_protocol is None
    assert c.get_extra_info("client_credential") is None

    server_tls_token = None
    while c.get_extra_info("auth_stage") == "TLS Handshake":
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

    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    # Matches the principal authenticated with the Negotiate phase - NTLMHash
    assert s.client_principal == ntlm_cred[0]

    # Matches the Password cred passed in, will not use the NTLMHash details as it wasn't enought for CredSSP
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == "delegate"
    assert client_credential.domain_name == ""
    assert client_credential.password == "password"

    _message_test(c, s)

    c = c.new_context()
    s = s.new_context()

    assert c.client_principal is None
    assert c.negotiated_protocol is None
    assert c.get_extra_info("client_credential") is None

    server_tls_token = None
    while c.get_extra_info("auth_stage") == "TLS Handshake":
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

    assert c.negotiated_protocol == "ntlm"
    assert s.negotiated_protocol == "ntlm"

    # Matches the principal authenticated with the Negotiate phase - NTLMHash
    assert s.client_principal == ntlm_cred[0]

    # Matches the Password cred passed in, will not use the NTLMHash details as it wasn't enought for CredSSP
    client_credential = s.get_extra_info("client_credential")
    assert isinstance(client_credential, TSPasswordCreds)
    assert client_credential.username == "delegate"
    assert client_credential.domain_name == ""
    assert client_credential.password == "password"

    _message_test(c, s)


def test_credssp_min_protocol_failure_initiator(ntlm_cred, monkeypatch):
    monkeypatch.setattr(spnego._credssp, "_CREDSSP_VERSION", 4)

    c = spnego.client(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", credssp_min_protocol=5
    )
    s = spnego.server(protocol="credssp")

    # The TLS handshake can differ based on the protocol selected, keep on looping until we see the auth_context set up
    # For NTLM the auth context will be present after the first exchange of NTLM tokens.
    server_tls_token = None
    while c._auth_context is None:  # type: ignore[attr-defined]
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    with pytest.raises(
        InvalidTokenError, match="The peer protocol version was 4 and did not meet the minimum requirements of 5"
    ):
        c.step(server_tls_token)


def test_credssp_min_protocol_failure_acceptor(ntlm_cred, monkeypatch):
    monkeypatch.setattr(spnego._credssp, "_CREDSSP_VERSION", 4)

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = spnego.server(protocol="credssp", credssp_min_protocol=5)

    # The TLS handshake can differ based on the protocol selected, keep on looping until we see the auth_context set up
    # For NTLM the auth context will be present after the first exchange of NTLM tokens.
    server_tls_token = None
    while True:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        if c.get_extra_info("auth_stage").startswith("Authentication"):
            break

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    with pytest.raises(
        InvalidTokenError, match="The peer protocol version was 4 and did not meet the minimum requirements of 5"
    ):
        s.step(client_tls_token)
