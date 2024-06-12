# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import os
import pathlib
import re
import socket

import pytest

import spnego
import spnego._ntlm as ntlm
import spnego.channel_bindings
import spnego.iov
from spnego._credential import CredentialCache
from spnego._ntlm_raw.crypto import md4
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
    InvalidTokenError,
    NoContextError,
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


def test_context_no_store_initiate():
    with pytest.raises(
        OperationNotAvailableError,
        match="No username or password was specified and the credential cache did not exist or contained no credentials",
    ):
        ntlm.NTLMProxy(CredentialCache(), usage="initiate")


def test_context_no_store_accept():
    with pytest.raises(
        OperationNotAvailableError,
        match="NTLM acceptor requires NTLM credential cache to be provided through the env var NTLM_USER_FILE set to a filepath",
    ):
        ntlm.NTLMProxy(CredentialCache(), usage="accept")


def test_iov_available():
    assert ntlm.NTLMProxy.iov_available() is True


def test_ntlm_invalid_usage():
    with pytest.raises(ValueError, match="Invalid usage 'test', must be initiate or accept"):
        ntlm.NTLMProxy("user", "pass", usage="test")


def test_ntlm_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid protocol 'fake', must be ntlm, kerberos, negotiate, or credssp"):
        ntlm.NTLMProxy("user", "pass", protocol="fake")


def test_ntlm_query_message_sizes_fail():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(NoContextError, match="Cannot get message sizes until context has been established"):
        n.query_message_sizes()


def test_ntlm_wrap_qop_invalid():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.wrap(b"data", qop=1)


def test_ntlm_wrap_no_sign_or_seal():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM wrap without integrity or confidentiality"):
        n.wrap(b"data")


def test_ntlm_wrap_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    with pytest.raises(NoContextError, match="Cannot wrap until context has been established"):
        n.wrap(b"data")


def test_ntlm_wrap_winrm_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    with pytest.raises(NoContextError, match="Cannot wrap until context has been established"):
        n.wrap_winrm(b"data")


def test_ntlm_unwrap_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(NoContextError, match="Cannot unwrap until context has been established"):
        n.unwrap(b"data")


def test_ntlm_unwrap_winrm_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(NoContextError, match="Cannot unwrap until context has been established"):
        n.unwrap_winrm(b"header", b"data")


def test_ntlm_wrap_iov_with_qop_fail():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.wrap_iov([], qop=1)


def test_ntlm_wrap_iov_no_sign_or_seal():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM wrap without integrity or confidentiality"):
        n.wrap_iov([])


def test_ntlm_wrap_iov_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    with pytest.raises(NoContextError, match="Cannot wrap until context has been established"):
        n.wrap_iov([])


def test_ntlm_wrap_iov_no_header():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov no IOV header buffer present"):
        n.wrap_iov([b""])


def test_ntlm_wrap_iov_no_data():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov no IOV data buffer present"):
        n.wrap_iov([spnego.iov.BufferType.header])


def test_ntlm_wrap_iov_multiple_header():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov must only be used with 1 header IOV buffer"):
        n.wrap_iov([spnego.iov.BufferType.header, b"", spnego.iov.BufferType.header])


def test_ntlm_wrap_iov_multiple_data():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov must only be used with 1 data IOV buffer"):
        n.wrap_iov([spnego.iov.BufferType.header, b"", b""])


def test_ntlm_wrap_iov_invalid_type():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov unsupported IOV buffer type padding"):
        n.wrap_iov([spnego.iov.BufferType.header, b"", spnego.iov.BufferType.padding])


def test_ntlm_wrap_iov_data_not_bytes():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov IOV data buffer at \\[1\\] must be bytes"):
        n.wrap_iov([spnego.iov.BufferType.header, (spnego.iov.BufferType.data, 1)])


def test_ntlm_wrap_iov_signonly_not_bytes():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_out = n._handle_out = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="wrap_iov IOV sign_only buffer at \\[1\\] must be bytes"):
        n.wrap_iov([spnego.iov.BufferType.header, (spnego.iov.BufferType.sign_only, 1)])


def test_ntlm_unwrap_iov_no_sign_or_seal():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(OperationNotAvailableError, match="NTLM unwrap without integrity or confidentiality"):
        n.unwrap_iov([])


def test_ntlm_unwrap_iov_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    with pytest.raises(NoContextError, match="Cannot unwrap until context has been established"):
        n.unwrap_iov([])


def test_ntlm_unwrap_iov_no_header():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov no IOV header buffer present"):
        n.unwrap_iov([b""])


def test_ntlm_unwrap_iov_no_data():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov no IOV data buffer present"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b"")])


def test_ntlm_unwrap_iov_multiple_header():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov must only be used with 1 header IOV buffer"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b""), b"", (spnego.iov.BufferType.header, b"")])


def test_ntlm_unwrap_iov_multiple_data():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov must only be used with 1 data IOV buffer"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b""), b"", b""])


def test_ntlm_unwrap_iov_invalid_type():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov unsupported IOV buffer type padding"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b""), b"", (spnego.iov.BufferType.padding, b"")])


def test_ntlm_unwrap_iov_data_not_bytes():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov IOV data buffer at \\[1\\] must be bytes"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b""), (spnego.iov.BufferType.data, 1)])


def test_ntlm_unwrap_iov_data_readonly_not_bytes():
    n = ntlm.NTLMProxy("user", "pass")
    n._context_attr = spnego.ContextReq.confidentiality | spnego.ContextReq.integrity
    n._sign_key_in = n._handle_in = 1  # type: ignore

    with pytest.raises(InvalidTokenError, match="unwrap_iov IOV data_readonly buffer at \\[1\\] must be bytes"):
        n.unwrap_iov([(spnego.iov.BufferType.header, b""), (spnego.iov.BufferType.data_readonly, 1)])


def test_ntlm_sign_qop_invalid():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(UnsupportedQop, match="Unsupported QoP value 1 specified for NTLM"):
        n.sign(b"data", qop=1)


def test_ntlm_sign_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(NoContextError, match="Cannot sign until context has been established"):
        n.sign(b"data")


def test_ntlm_verify_no_context():
    n = ntlm.NTLMProxy("user", "pass")
    with pytest.raises(NoContextError, match="Cannot verify until context has been established"):
        n.verify(b"data", b"mic")


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


def test_ntlm_with_invalid_surrogate_pair_pass(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    username = "user"

    # This is a password for a gMSA account used as a test. It is technically
    # a UTF-16-LE string value but contains invalid surrogate pairs which is
    # important for testing.
    b_gmsa_password = (
        b"\x91\x45\xC9\xD1\x1D\x74\xA9\xE2"
        b"\x27\x5A\x4C\xBE\x13\xC1\xE2\xF4"
        b"\x89\x94\x49\x5E\x01\x60\xDD\xBA"
        b"\xE2\xD9\x12\x53\xF0\xEB\x96\x38"
        b"\xB3\x8B\xD2\x17\xC9\xCC\x9B\xB6"
        b"\xC7\xF0\xCC\x8F\xEB\x75\x03\x77"
        b"\x30\xD3\xE2\x6C\xE6\x00\x04\x39"
        b"\xF5\x5F\xD9\xA5\xD8\xEF\xB3\x9F"
        b"\xDE\x4A\xB5\xC1\x51\xC0\x44\x3B"
        b"\x66\xC6\xF4\x68\x8D\xE1\x78\xBE"
        b"\x3D\x35\x34\xC7\x4A\x91\x6D\x7B"
        b"\x3C\xE0\x6E\x1C\xE9\xA9\x96\x6E"
        b"\xDA\x09\x6A\x39\x1A\x2E\x5F\xD2"
        b"\x92\x86\x46\x3B\x8B\x9A\xD3\xCE"
        b"\xED\x83\x03\x2A\x33\x0D\xBC\x06"
        b"\x91\xC6\x0C\xB1\x69\x5D\x2D\x59"
        b"\xE0\x66\x18\x99\x00\xD1\x5A\x55"
        b"\x85\xA3\xA8\x23\x0E\xCC\x16\x08"
        b"\xF9\xE1\x9D\xF7\x09\x24\x66\xB3"
        b"\x56\x6D\xC8\x2B\x4D\x33\x7F\x1A"
        b"\xED\x69\x24\x09\xB1\x0C\xD6\x51"
        b"\xBB\x62\xD9\x82\xD4\xA6\x1D\x91"
        b"\x6F\xC4\xB2\xB0\x45\x9A\x40\x5A"
        b"\xEC\x81\x71\xA1\x48\xB3\x52\x37"
        b"\x26\x72\x98\x01\x22\x31\xF2\xD8"
        b"\xD4\x83\x7B\xF3\xCA\xD5\x81\x24"
        b"\xDC\xA9\xC2\xBF\x6D\x8E\x87\x7D"
        b"\x24\x87\x49\x6C\x46\xE6\x67\x8B"
        b"\x10\x69\x00\x04\xCA\x17\x4B\xC8"
        b"\x04\x33\x69\x06\x61\x57\xB9\xC7"
        b"\x3B\xFC\x0A\xCD\x35\xCE\x61\xB9"
        b"\x87\x3B\xFF\x3A\x2D\x55\x67\xF6"
    )

    tmp_creds = tmp_path / "ntlm.cred"
    with open(tmp_creds, mode="w") as fd:
        nt_hash = base64.b16encode(md4(b_gmsa_password)).decode()
        fd.write(f"{username}:1:00000000000000000000000000000000:{nt_hash}:[U]:LCT-1589398321")

    monkeypatch.setenv("NTLM_USER_FILE", str(tmp_creds.absolute()))

    c = spnego.client(
        username,
        b_gmsa_password.decode("utf-16-le", errors="surrogatepass"),
        hostname=socket.gethostname(),
        options=spnego.NegotiateOptions.use_ntlm,
        protocol="ntlm",
    )
    s = spnego.server(options=spnego.NegotiateOptions.use_ntlm, protocol="ntlm")

    s.step(c.step(s.step(c.step())))

    assert c.complete
    assert s.complete


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


def test_ntlm_iov_wrapping(ntlm_cred):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    s = spnego.server(protocol="ntlm")

    s.step(c.step(s.step(c.step())))

    res1 = c.wrap_iov(
        [
            (spnego.iov.BufferType.sign_only, b"sign 1"),
            b"data",
            (spnego.iov.BufferType.data_readonly, b"sign 2"),
            spnego.iov.BufferType.header,
        ]
    )
    assert isinstance(res1, spnego.IOVWrapResult)
    assert res1.encrypted
    assert len(res1.buffers) == 4
    assert res1.buffers[0].data == b"sign 1"
    assert res1.buffers[1].data != b"data"
    assert res1.buffers[2].data == b"sign 2"
    assert len(res1.buffers[3].data or b"") == 16

    res2 = s.unwrap_iov(res1.buffers)
    assert isinstance(res2, spnego.IOVUnwrapResult)
    assert res2.encrypted
    assert res2.qop == 0
    assert len(res2.buffers) == 4
    assert res2.buffers[0].data == b"sign 1"
    assert res2.buffers[1].data == b"data"
    assert res2.buffers[2].data == b"sign 2"
    assert res2.buffers[3].data == res1.buffers[3].data

    res3 = s.wrap_iov(
        [
            (spnego.iov.BufferType.sign_only, b"sign 1"),
            b"data",
            (spnego.iov.BufferType.data_readonly, b"sign 2"),
            spnego.iov.BufferType.header,
        ]
    )
    assert isinstance(res3, spnego.IOVWrapResult)
    assert res3.encrypted
    assert len(res3.buffers) == 4
    assert res3.buffers[0].data == b"sign 1"
    assert res3.buffers[1].data != b"data"
    assert res3.buffers[2].data == b"sign 2"
    assert len(res3.buffers[3].data or b"") == 16

    res4 = c.unwrap_iov(res3.buffers)
    assert isinstance(res4, spnego.IOVUnwrapResult)
    assert res4.encrypted
    assert res4.qop == 0
    assert len(res4.buffers) == 4
    assert res4.buffers[0].data == b"sign 1"
    assert res4.buffers[1].data == b"data"
    assert res4.buffers[2].data == b"sign 2"
    assert res4.buffers[3].data == res3.buffers[3].data


def test_ntlm_iov_unwrapping_as_stream(ntlm_cred):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    s = spnego.server(protocol="ntlm")

    s.step(c.step(s.step(c.step())))

    res1 = c.wrap_iov(
        [
            b"data",
            spnego.iov.BufferType.header,
        ]
    )
    assert isinstance(res1, spnego.IOVWrapResult)
    assert res1.encrypted
    assert len(res1.buffers) == 2
    assert res1.buffers[0].data != b"data"
    assert len(res1.buffers[1].data or b"") == 16

    msg = (res1.buffers[1].data or b"") + (res1.buffers[0].data or b"")
    res2 = s.unwrap_iov(
        [
            (spnego.iov.BufferType.stream, msg),
            spnego.iov.BufferType.data,
        ]
    )
    assert isinstance(res2, spnego.IOVUnwrapResult)
    assert res2.encrypted
    assert res2.qop == 0
    assert len(res2.buffers) == 2
    assert res2.buffers[1].data == b"data"

    res3 = s.wrap_iov(
        [
            spnego.iov.BufferType.header,
            b"data",
        ]
    )
    assert isinstance(res3, spnego.IOVWrapResult)
    assert res3.encrypted
    assert len(res3.buffers) == 2
    assert len(res3.buffers[0].data or b"") == 16
    assert res3.buffers[1].data != b"data"

    msg = (res3.buffers[0].data or b"") + (res3.buffers[1].data or b"")
    res4 = c.unwrap_iov(
        [
            (spnego.iov.BufferType.stream, msg),
            spnego.iov.BufferType.data,
        ]
    )
    assert isinstance(res4, spnego.IOVUnwrapResult)
    assert res4.encrypted
    assert res4.qop == 0
    assert len(res4.buffers) == 2
    assert res4.buffers[1].data == b"data"
