# -*- coding: utf-8 -*-
# (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import sys

import pytest

from spnego._text import to_text
from spnego.exceptions import WinError

SKIP = False
try:
    import spnego._sspi_raw as sspi
except ImportError:
    SKIP = True


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_desc_repr():
    sec_buffer_desc = sspi.SecBufferDesc([sspi.SecBuffer(1, b"\x00\x01"), sspi.SecBuffer(2, b"\x02\x03")])
    actual = repr(sec_buffer_desc)

    assert actual == r"<spnego._sspi_raw.sspi.SecBufferDesc(ulVersion=0, cBuffers=2)>"


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_desc_str():
    sec_buffer_desc = sspi.SecBufferDesc([sspi.SecBuffer(1, b"\x00\x01"), sspi.SecBuffer(2, b"\x02\x03")])
    actual = str(sec_buffer_desc)

    assert actual == r"SecBufferDesc(ulVersion=0, cBuffers=2)"


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_desc_version():
    sec_buffer_desc = sspi.SecBufferDesc([sspi.SecBuffer(1, b"\x00\x01"), sspi.SecBuffer(2, b"\x02\x03")])
    assert sec_buffer_desc.version == 0
    sec_buffer_desc.version = 1
    assert sec_buffer_desc.version == 1


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_invalid_init():
    with pytest.raises(ValueError, match="Only an empty buffer can be created with length"):
        sspi.SecBuffer(1, buffer=b"abc", length=10)


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
@pytest.mark.parametrize(
    "buffer, expected",
    [
        (b"abc", 3),
        (b"\x01\x02\x03\x04\x05", 5),
    ],
)
def test_sec_buffer_length(buffer, expected):
    assert len(sspi.SecBuffer(1, buffer=buffer)) == expected


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_repr():
    sec_buffer = sspi.SecBuffer(1, b"\x01\x02\x03\x04")
    actual = repr(sec_buffer)

    if sys.version_info[0] == 2:
        assert actual == r"<spnego._sspi_raw.sspi.SecBuffer(cbBuffer=4, BufferType=1, pvBuffer='\x01\x02\x03\x04')>"

    else:
        assert actual == r"<spnego._sspi_raw.sspi.SecBuffer(cbBuffer=4, BufferType=1, pvBuffer=b'\x01\x02\x03\x04')>"


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_sec_buffer_str():
    sec_buffer = sspi.SecBuffer(1, b"\x01\x02\x03\x04")
    actual = str(sec_buffer)

    if sys.version_info[0] == 2:
        assert actual == r"SecBuffer(cbBuffer=4, BufferType=1, pvBuffer='\x01\x02\x03\x04')"

    else:
        assert actual == r"SecBuffer(cbBuffer=4, BufferType=1, pvBuffer=b'\x01\x02\x03\x04')"


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
@pytest.mark.parametrize(
    "username, domain, expected",
    [
        ("username", "domain", "domain\\username"),
        ("username@DOMAIN", "", "username@DOMAIN"),
        ("username@DOMAIN", None, "username@DOMAIN"),
        (None, "domain", "domain\\"),
        (None, None, ""),
        ("", "", ""),
        (
            "user" + to_text(b"\xF0\x9D\x84\x9E"),
            "domain" + to_text(b"\xF0\x9D\x84\x9E"),
            "domain{0}\\user{0}".format(to_text(b"\xF0\x9D\x84\x9E")),
        ),
    ],
)
def test_win_nt_auth_identity(username, domain, expected):
    identity = sspi.WinNTAuthIdentity(username, domain, "password")

    assert repr(identity) == "<spnego._sspi_raw.sspi.WinNTAuthIdentity %s>" % expected
    assert str(identity) == expected


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_win_nt_auth_identity_set_username():
    identity = sspi.WinNTAuthIdentity("original", None, None)

    test_user = "user" + to_text(b"\xF0\x9D\x84\x9E")
    identity.username = test_user
    assert identity.username == test_user
    assert str(identity) == test_user


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_win_nt_auth_identity_set_domain():
    identity = sspi.WinNTAuthIdentity(None, "original", None)

    test_domain = "domain" + to_text(b"\xF0\x9D\x84\x9E")
    identity.domain = test_domain
    assert identity.domain == test_domain
    assert str(identity) == test_domain + "\\"


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_win_nt_auth_identity_set_password():
    identity = sspi.WinNTAuthIdentity(None, None, "original")

    test_password = "password" + to_text(b"\xF0\x9D\x84\x9E")
    identity.password = test_password
    assert identity.password == test_password


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_accept_security_context_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.accept_security_context(sspi.Credential(), sspi.SecurityContext(), sspi.SecBufferDesc([]))


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_acquire_credentials_handle_fail():
    with pytest.raises(WinError, match="The requested security package does not exist"):
        sspi.acquire_credentials_handle(None, "fake package")


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_decrypt_message_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.decrypt_message(sspi.SecurityContext(), sspi.SecBufferDesc([]))


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_encrypt_message_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.encrypt_message(sspi.SecurityContext(), sspi.SecBufferDesc([]))


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_initialize_security_context_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.initialize_security_context(sspi.Credential(), sspi.SecurityContext(), "target_name")


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_make_signature_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.make_signature(sspi.SecurityContext(), 0, sspi.SecBufferDesc([]))


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_query_context_attributes_unknown():
    with pytest.raises(NotImplementedError, match="Only names, package_info, session_key, or sizes is implemented"):
        sspi.query_context_attributes(sspi.SecurityContext(), 1024)


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
@pytest.mark.parametrize(
    "attribute",
    [
        0,  # sizes
        9,  # session_key
        10,  # package_info
    ],
)
def test_query_context_attributes_invalid_handle(attribute):
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.query_context_attributes(sspi.SecurityContext(), attribute)


@pytest.mark.skipif(SKIP, reason="Can only test Cython code on Windows with compiled code.")
def test_verify_signature_fail():
    with pytest.raises(WinError, match="The handle specified is invalid"):
        sspi.verify_signature(sspi.SecurityContext(), sspi.SecBufferDesc([]))
