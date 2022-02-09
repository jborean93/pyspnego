# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import socket

import pytest

import spnego._credssp as credssp
from spnego._credssp_structures import NegoData, TSRequest
from spnego.exceptions import (
    BadBindingsError,
    FeatureMissingError,
    InvalidTokenError,
    NegotiateOptions,
    OperationNotAvailableError,
    SpnegoError,
)
from spnego.tls import default_tls_context


@pytest.mark.parametrize(
    "expected, usage, nonce",
    [
        (b"\x00\x01", "initiate", None),
        (
            b"\x45\x90\xC2\x6C\x83\x7D\xAC\xDF\x3D\xA8\xFA\xE5\x78\x26\x4D\x9E"
            b"\x45\x48\x6A\xFC\x39\x51\xF2\x1E\xF3\x57\x06\x4C\xD5\x5F\xBB\xB5",
            "initiate",
            b"\x00\x00",
        ),
        (b"\x01\x01", "accept", None),
        (
            b"\xCD\xF4\xFF\xEE\x6C\xB6\x39\x5E\x5B\x69\x2C\x2D\xA3\x97\x38\x6F"
            b"\x6A\x1E\xAB\x2D\x3A\x62\x71\x81\x6A\x04\xC7\xA2\x91\x4D\x33\x3F",
            "accept",
            b"\x00\x00",
        ),
    ],
)
def test_pub_key_auth(expected, usage, nonce):
    actual = credssp._get_pub_key_auth(b"\x00\x01", usage, nonce=nonce)

    assert actual == expected


@pytest.mark.parametrize(
    "protocol, cipher, expected",
    [
        ["TLSv1.3", "TLS_AES_128_GCM_SHA256", 17],
        ["TLSv1.3", "TLS_AES_256_GCM_SHA384", 17],
        ["TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", 16],
        ["TLSv1.2", "RC4-MD5", 16],
        ["TLSv1.2", "ECDH-ECDSA-3DES-SHA256", 34],
        ["TLSv1.2", "ECDH-RSA-AES-SHA384", 50],
        ["TLSv1.2", "ECDH-RSA-AES", 2],
    ],
)
def test_get_credssp_trailer_length(protocol, cipher, expected):
    actual = credssp._tls_trailer_length(30, protocol, cipher)
    assert actual == expected


def test_credssp_no_iov():
    assert not credssp.CredSSPProxy("username", "password").iov_available()


def test_credssp_no_session_key():
    with pytest.raises(FeatureMissingError, match="The protocol selected does not support getting the session key"):
        credssp.CredSSPProxy("user", "password", options=NegotiateOptions.session_key)


def test_credssp_fail_getting_session_key():
    context = credssp.CredSSPProxy("username", "password")

    with pytest.raises(OperationNotAvailableError, match="CredSSP does not have a session key to share"):
        _ = context.session_key


def test_credssp_wrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").wrap_iov([])


def test_credssp_unwrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").unwrap_iov([])


def test_credssp_sign_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer signing"):
        credssp.CredSSPProxy("username", "password").sign(b"")


def test_credssp_verify_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer verification"):
        credssp.CredSSPProxy("username", "password").verify(b"", b"")


def test_credssp_wrap_no_context():
    with pytest.raises(SpnegoError, match="Invalid TLS state when wrapping data"):
        credssp.CredSSPProxy("username", "password").wrap(b"data")


def test_credssp_invalid_handshake(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], protocol="credssp")
    s = credssp.CredSSPProxy(None, None, protocol="credssp", usage="accept")

    server_hello = s.step(c.step())
    assert server_hello is not None

    with pytest.raises(InvalidTokenError, match="TLS handshake for CredSSP"):
        c.step(b"\x00" + server_hello)


def test_credssp_server_without_pub_key():
    context = default_tls_context(usage="accept")
    with pytest.raises(OperationNotAvailableError, match="Provided tls context does not have a public key set"):
        credssp.CredSSPProxy("username", "password", usage="accept", credssp_tls_context=context)


@pytest.mark.parametrize("version", [2, 5])
def test_credssp_invalid_client_authentication_v2(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    actual = s.step(c.wrap(bad_request.pack()).data)

    # On CredSSP v2 or 5 there is no error message from the server, just no token
    assert actual is None


@pytest.mark.parametrize("version", [3, 4, 6])
def test_credssp_invalid_client_authentication(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    assert server_tls_token is not None
    c.unwrap(server_tls_token)
    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    error_msg = s.step(c.wrap(bad_request.pack()).data)

    expected = re.escape("Received NTStatus in TSRequest from acceptor, Context: Authentication")
    with pytest.raises(InvalidTokenError, match=expected):
        c.step(error_msg)


def test_credssp_no_pub_key_after_auth(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept")

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    # Send back a TSRequest without the public key.
    assert ntlm3_pub_key is not None
    s.unwrap(ntlm3_pub_key)
    ts_request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="Acceptor did not response with pubKeyAuth info"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_initiator(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp", options=options)
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept", options=options)

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    s_auth_context = s._auth_context
    assert s_auth_context is not None

    # Send back a TSRequest with a bad pub_key_auth value.
    assert ntlm3_pub_key is not None
    request = TSRequest.unpack(s.unwrap(ntlm3_pub_key).data)
    assert request.nego_tokens is not None
    s_auth_context.step(request.nego_tokens[0].nego_token)
    ts_request = TSRequest(credssp._CREDSSP_VERSION, pub_key_auth=s_auth_context.wrap(b"bad").data)

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_acceptor(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp", options=options)
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept", options=options)

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    # Craft the TSRequest with the NTLMv3 token and invalid pub_key_auth
    assert server_tls_token is not None
    ntlm2_request = TSRequest.unpack(c.unwrap(server_tls_token).data)
    assert ntlm2_request.nego_tokens is not None
    ntlm3 = c._auth_context.step(ntlm2_request.nego_tokens[0].nego_token)
    assert ntlm3 is not None

    request = TSRequest(
        credssp._CREDSSP_VERSION, nego_tokens=NegoData(ntlm3), pub_key_auth=c._auth_context.wrap(b"bad").data
    )

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        s.step(c.wrap(request.pack()).data)


def test_credssp_no_credential(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.getfqdn(), protocol="credssp", options=options)
    s = credssp.CredSSPProxy(None, None, hostname=socket.getfqdn(), protocol="credssp", usage="accept", options=options)

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert ntlm3_pub_key is not None

    pub_key_resp = s.step(ntlm3_pub_key)
    assert pub_key_resp is not None
    server_pub_key = TSRequest.unpack(c.unwrap(pub_key_resp).data)

    # Unpack the TSRequest properly and craft a TSRequest without a credential
    assert server_pub_key.pub_key_auth is not None
    c._auth_context.unwrap(server_pub_key.pub_key_auth)

    request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="No credential received on CredSSP TSRequest from initiator"):
        s.step(c.wrap(request.pack()).data)
