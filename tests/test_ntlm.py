# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import os
import re
import socket

import pytest

import spnego
import spnego._ntlm as ntlm
import spnego.channel_bindings
from spnego._credential import CredentialCache
from spnego._ntlm_raw.messages import (
    Authenticate,
    AvId,
    Challenge,
    FileTime,
    Negotiate,
    NegotiateFlags,
    TargetInfo,
    Version,
)
from spnego._text import to_bytes, to_text
from spnego.exceptions import (
    BadBindingsError,
    BadMICError,
    FeatureMissingError,
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
    tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$" ".creds")

    monkeypatch.setenv("NTLM_USER_FILE", tmp_creds)

    actual = ntlm._get_credential_file()
    assert actual is None


def test_get_credential_file(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$" ".creds")
    with open(tmp_creds, mode="wb") as fd:
        fd.write(b"data")

    monkeypatch.setenv("NTLM_USER_FILE", tmp_creds)

    actual = ntlm._get_credential_file()
    assert actual == to_text(tmp_creds)


@pytest.mark.parametrize(
    "line, username, domain, lm_hash, nt_hash, input",
    [
        (
            "domain:Username:password",
            "username",
            "domain",
            "E52CAC67419A9A224A3B108F3FA6CB6D",
            "8846F7EAEE8FB117AD06BDD830B7586C",
            CredentialCache(username="domain\\username"),
        ),
        (
            "domain:Username:password\ndomain:other:pass2",
            "Username",
            "domain",
            "E52CAC67419A9A224A3B108F3FA6CB6D",
            "8846F7EAEE8FB117AD06BDD830B7586C",
            None,
        ),
        (
            "fake\ndomain:username:password",
            "username",
            "domain",  # newline or garbage data  in file won't fail
            "E52CAC67419A9A224A3B108F3FA6CB6D",
            "8846F7EAEE8FB117AD06BDD830B7586C",
            CredentialCache("domain\\username"),
        ),
        (
            ":username@DOMAIN.COM:password",
            "username@DOMAIN.COM",
            None,
            "E52CAC67419A9A224A3B108F3FA6CB6D",
            "8846F7EAEE8FB117AD06BDD830B7586C",
            CredentialCache("username@DOMAIN.COM"),
        ),
        (
            "testuser:1000:278623D830DABE161104594F8C2EF12B:C3C6F4FD8A02A6C1268F1A8074B6E7E0:[U]:LCT-1589398321",
            "testuser",
            None,
            "278623D830DABE161104594F8C2EF12B",
            "C3C6F4FD8A02A6C1268F1A8074B6E7E0",
            CredentialCache("testuser"),
        ),
        (
            "TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321",
            "testuser",
            "testdom",
            "4588C64B89437893AAD3B435B51404EE",
            "65202355FA01AEF26B89B19E00F52679",
            CredentialCache("testdom\\testuser"),
        ),
        (
            "TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321",
            "testuser",
            "testdom",
            "4588C64B89437893AAD3B435B51404EE",
            "65202355FA01AEF26B89B19E00F52679",
            CredentialCache("testdom\\testuser"),
        ),
        (
            "testuser@TESTDOM.COM:1000:00000000000000000000000000000000:8ADB9B997580D69E69CAA2BBB68F4697:[U]:LCT-1589398321",
            "testuser@testdom.com",
            None,
            "00000000000000000000000000000000",
            "8ADB9B997580D69E69CAA2BBB68F4697",
            CredentialCache("testuser@testdom.com"),
        ),
    ],
)
def test_get_credential_from_file(line, username, domain, lm_hash, nt_hash, input, tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$" ".creds")
    monkeypatch.setenv("NTLM_USER_FILE", tmp_creds)
    with open(tmp_creds, mode="wb") as fd:
        fd.write(to_bytes(line))

    actual = ntlm._NTLMCredential(input)
    assert actual.username == username
    assert actual.domain == domain
    assert actual.lm_hash == base64.b16decode(lm_hash)
    assert actual.nt_hash == base64.b16decode(nt_hash)


def test_get_credential_from_file_no_matches(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$" ".creds")
    monkeypatch.setenv("NTLM_USER_FILE", tmp_creds)
    with open(tmp_creds, mode="wb") as fd:
        fd.write(b"domain:username:password")

    with pytest.raises(
        SpnegoError, match="Failed to find any matching credential in NTLM_USER_FILE " "credential store."
    ):
        ntlm._NTLMCredential(CredentialCache("fake\\username"))


@pytest.mark.parametrize("level", [-1, 6])
def test_invalid_lm_compat_level(level, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", str(level))

    expected = "Invalid LM_COMPAT_LEVEL %s, must be between 0 and 5" % level
    with pytest.raises(SpnegoError, match=re.escape(expected)):
        ntlm.NTLMProxy("user", "pass")


@pytest.mark.parametrize("usage", ["initiate", "accept"])
def test_context_no_store(usage):
    with pytest.raises(
        OperationNotAvailableError, match="Retrieving NTLM store without NTLM_USER_FILE set to a " "filepath"
    ):
        ntlm.NTLMProxy(CredentialCache(), usage=usage)


def test_iov_available():
    assert ntlm.NTLMProxy.iov_available() is False


def test_ntlm_invalid_usage():
    with pytest.raises(ValueError, match="Invalid usage 'test', must be initiate or accept"):
        ntlm.NTLMProxy("user", "pass", usage="test")


def test_ntlm_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid protocol 'fake', must be ntlm, kerberos, negotiate, or credssp"):
        ntlm.NTLMProxy("user", "pass", protocol="fake")


def test_ntlm_iov_not_available():
    expected = (
        "The system is missing the GSSAPI IOV extension headers or NTLM or CredSSP is being requested, "
        "cannot utilize wrap_iov and unwrap_iov"
    )
    with pytest.raises(FeatureMissingError, match=re.escape(expected)):
        ntlm.NTLMProxy("user", "pass", options=spnego.NegotiateOptions.wrapping_iov)


def test_ntlm_wrap_qop_invalid():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.wrap(b"data", qop=1)


def test_ntlm_wrap_no_sign_or_seal():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM wrap without integrity or confidentiality"):
        n.wrap(b"data")


def test_ntlm_wrap_iov_fail():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM does not offer IOV wrapping"):
        n.wrap_iov([])


def test_ntlm_unwrap_iov_fail():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM does not offer IOV wrapping"):
        n.unwrap_iov([])


def test_ntlm_sign_qop_invalid():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.sign(b"data", qop=1)


def test_ntlm_no_encoding_flags():
    negotiate = memoryview(bytearray(get_data("ntlm_negotiate")))
    negotiate[12:16] = b"\x00\x00\x00\x00"

    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(
        SpnegoError,
        match="Neither NEGOTIATE_OEM or NEGOTIATE_UNICODE flags were set, cannot derive " "encoding for text fields",
    ):
        n._step_accept_negotiate(negotiate.tobytes())


@pytest.mark.parametrize(
    "client_opt, present",
    [
        (spnego.NegotiateOptions.use_ntlm, False),
        (spnego.NegotiateOptions.use_ntlm, True),
        (spnego.NegotiateOptions.use_gssapi, True),
        (spnego.NegotiateOptions.use_sspi, True),
    ],
)
def test_ntlm_bad_bindings(client_opt, present, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi:
        if "ntlm" not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through GSSAPI")

    elif client_opt & spnego.NegotiateOptions.use_sspi:
        if "ntlm" not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through SSPI")

    initiator_cbt = None
    if present:
        initiator_cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-host-data:bad")

    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=client_opt,
        protocol="ntlm",
        channel_bindings=initiator_cbt,
    )

    acceptor_cbt = spnego.channel_bindings.GssChannelBindings(application_data=b"tls-host-data:test")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm", channel_bindings=acceptor_cbt)

    auth = c.step(s.step(c.step()))

    if present:
        expected = "Acceptor bindings do not match initiator bindings"

    else:
        expected = "Acceptor bindings specified but not present in initiator response"

    with pytest.raises(BadBindingsError, match=expected):
        s.step(auth)


def test_ntlm_bad_mic(ntlm_cred):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = memoryview(bytearray(c.step(s.step(c.step())) or b""))
    auth[64:80] = b"\x01" * 16

    with pytest.raises(InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        s.step(auth.tobytes())


@pytest.mark.parametrize(
    "env_var, expected",
    [
        (None, to_text(socket.gethostname()).upper()),
        ("", None),
        ("custom", "custom"),
    ],
)
def test_ntlm_workstation_override(env_var, expected, ntlm_cred, monkeypatch):
    if env_var is not None:
        monkeypatch.setenv("NETBIOS_COMPUTER_NAME", env_var)

    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )

    b_negotiate = c.step()
    assert b_negotiate is not None
    negotiate = Negotiate.unpack(b_negotiate)

    flags = (
        negotiate.flags
        | NegotiateFlags.request_target
        | NegotiateFlags.ntlm
        | NegotiateFlags.always_sign
        | NegotiateFlags.target_info
        | NegotiateFlags.target_type_server
    )

    server_challenge = os.urandom(8)
    target_name = to_text(socket.gethostname()).upper()

    target_info = TargetInfo()
    target_info[AvId.nb_computer_name] = target_name
    target_info[AvId.nb_domain_name] = "WORKSTATION"
    target_info[AvId.dns_computer_name] = to_text(socket.getfqdn())
    target_info[AvId.timestamp] = FileTime.now()

    version = Version(10, 0, 0, 1)
    challenge = Challenge(flags, server_challenge, target_name=target_name, target_info=target_info, version=version)

    b_auth = c.step(challenge.pack())
    assert b_auth is not None
    auth = Authenticate.unpack(b_auth)

    assert auth.workstation == expected


@pytest.mark.parametrize(
    "include_time, expected",
    [
        # If the challenge didn't contain the time then the client should generate it's own otherwise it uses the challenge
        # time.
        (True, 0),
        (False, 1),
    ],
)
def test_ntlm_custom_time(include_time, expected, ntlm_cred, mocker, monkeypatch):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )

    b_negotiate = c.step()
    assert b_negotiate is not None
    negotiate = Negotiate.unpack(b_negotiate)

    flags = (
        negotiate.flags
        | NegotiateFlags.request_target
        | NegotiateFlags.ntlm
        | NegotiateFlags.always_sign
        | NegotiateFlags.target_info
        | NegotiateFlags.target_type_server
    )

    server_challenge = os.urandom(8)
    target_name = to_text(socket.gethostname()).upper()

    target_info = TargetInfo()
    target_info[AvId.nb_computer_name] = target_name
    target_info[AvId.nb_domain_name] = "WORKSTATION"
    target_info[AvId.dns_computer_name] = to_text(socket.getfqdn())

    if include_time:
        target_info[AvId.timestamp] = FileTime.now()

    challenge = Challenge(flags, server_challenge, target_name=target_name, target_info=target_info)

    mock_now = mocker.MagicMock()
    mock_now.side_effect = FileTime.now
    monkeypatch.setattr(FileTime, "now", mock_now)

    c.step(challenge.pack())
    assert c.complete
    assert mock_now.call_count == expected


def test_ntlm_no_key_exch(ntlm_cred):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    c._context_req &= ~0x40000000  # NTLMSSP_NEGOTIATE_KEY_EXCH

    auth = c.step(s.step(c.step()))
    s.step(auth)

    # Make sure EncryptedRandomSessionKeyFields was set to 0 (no KEY_EXCH).
    assert auth is not None
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


def test_ntlm_lm_request(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = memoryview(bytearray(c.step(s.step(c.step())) or b""))
    auth[20:28] = b"\x00" * 8

    s.step(auth.tobytes())

    assert c.complete
    assert s.complete


def test_ntlm_no_lm_allowed(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )

    monkeypatch.setenv("LM_COMPAT_LEVEL", "4")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = memoryview(bytearray(c.step(s.step(c.step())) or b""))
    auth[20:28] = b"\x00" * 8

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject LM responses"):
        s.step(auth)


def test_ntlm_nt_v1_request(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )

    monkeypatch.setenv("LM_COMPAT_LEVEL", "4")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = c.step(s.step(c.step()))

    s.step(auth)

    assert c.complete
    assert s.complete


def test_ntlm_no_nt_v1_allowed(ntlm_cred, monkeypatch):
    monkeypatch.setenv("LM_COMPAT_LEVEL", "0")
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )

    monkeypatch.setenv("LM_COMPAT_LEVEL", "5")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = c.step(s.step(c.step()))

    with pytest.raises(InvalidTokenError, match="Acceptor settings are set to reject NTv1 responses"):
        s.step(auth)


@pytest.mark.parametrize(
    "client_opt",
    [
        spnego.NegotiateOptions.use_ntlm,
        spnego.NegotiateOptions.use_gssapi,
        spnego.NegotiateOptions.use_sspi,
    ],
)
def test_ntlm_invalid_password(client_opt, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi:
        if "ntlm" not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through GSSAPI")

    elif client_opt & spnego.NegotiateOptions.use_sspi:
        if "ntlm" not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through SSPI")

    c = spnego.client(ntlm_cred[0], "Invalid", hostname=socket.gethostname(), options=client_opt, protocol="ntlm")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = c.step(s.step(c.step()))

    with pytest.raises(InvalidTokenError, match="Invalid NTLM response from initiator"):
        s.step(auth)


@pytest.mark.parametrize(
    "client_opt",
    [
        spnego.NegotiateOptions.use_ntlm,
        spnego.NegotiateOptions.use_gssapi,
        spnego.NegotiateOptions.use_sspi,
    ],
)
def test_ntlm_verify_fail(client_opt, ntlm_cred):
    if client_opt & spnego.NegotiateOptions.use_gssapi:
        if "ntlm" not in spnego._gss.GSSAPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through GSSAPI")

    elif client_opt & spnego.NegotiateOptions.use_sspi:
        if "ntlm" not in spnego._sspi.SSPIProxy.available_protocols():
            pytest.skip("Test requires NTLM to be available through SSPI")

    c = spnego.client(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), options=client_opt, protocol="ntlm")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    s.step(c.step(s.step(c.step())))

    c.sign(b"data")
    sig = c.sign(b"data 2")

    with pytest.raises(BadMICError, match="Invalid Message integrity Check"):
        s.verify(b"data", sig)


def test_ntlm_anon_response(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    auth = Authenticate.unpack(c.step(s.step(c.step())) or b"")
    anon_auth = Authenticate(flags=auth.flags, lm_challenge_response=b"\x00", nt_challenge_response=b"").pack()

    with pytest.raises(OperationNotAvailableError, match="Anonymous user authentication not implemented"):
        s.step(anon_auth)
