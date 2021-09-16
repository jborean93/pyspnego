# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import socket

import pytest

import spnego._sspi
import spnego.iov
from spnego.exceptions import InvalidCredentialError


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_build_iov_list(ntlm_cred):
    c = spnego._sspi.SSPIProxy(ntlm_cred[0], ntlm_cred[1], protocol="ntlm")
    c._security_trailer = 10
    c._block_size = 2

    actual = c._build_iov_list(
        [
            (spnego.iov.BufferType.header, b"\x01"),
            (spnego.iov.BufferType.data, 5),
            (spnego.iov.BufferType.padding, True),
            spnego.iov.BufferType.header,
            spnego.iov.BufferType.stream,
            b"\x02",
        ],
        c._convert_iov_buffer,
    )

    assert len(actual) == 6
    assert actual[0].buffer_type == spnego.iov.BufferType.header
    assert actual[0].buffer == b"\x01"
    assert actual[1].buffer_type == spnego.iov.BufferType.data
    assert actual[1].buffer is not None
    assert len(actual[1].buffer) == 5
    assert actual[2].buffer_type == spnego.iov.BufferType.padding
    assert actual[2].buffer is not None
    assert len(actual[2].buffer) == 2
    assert actual[3].buffer_type == spnego.iov.BufferType.header
    assert actual[3].buffer is not None
    assert len(actual[3].buffer) == 10
    assert actual[4].buffer_type == spnego.iov.BufferType.stream
    assert actual[4].buffer is None
    assert actual[5].buffer_type == spnego.iov.BufferType.data
    assert actual[5].buffer == b"\x02"


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_build_iov_list_fail_auto_alloc(ntlm_cred):
    c = spnego._sspi.SSPIProxy(ntlm_cred[0], ntlm_cred[1], protocol="ntlm")
    c._security_trailer = 10
    c._block_size = 2

    with pytest.raises(ValueError, match="Cannot auto allocate buffer of type BufferType.data"):
        c._build_iov_list([(spnego.iov.BufferType.data, True)], c._convert_iov_buffer)


def test_no_sspi_library(monkeypatch):
    monkeypatch.setattr(spnego._sspi, "HAS_SSPI", False)

    with pytest.raises(ImportError, match="SSPIProxy requires the SSPI Cython extension to be compiled"):
        spnego._sspi.SSPIProxy()


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_sspi_invalid_qop():
    c = spnego._sspi.SSPIProxy("user", "pass")

    with pytest.raises(ValueError, match="Cannot set qop with SECQOP_WRAP_NO_ENCRYPT and encrypt=True"):
        c.wrap(b"\x00", True, qop=0x80000001)


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_sspi_wrap_no_encryption(ntlm_cred):
    c = spnego._sspi.SSPIProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname())
    s = spnego._sspi.SSPIProxy(usage="accept")

    s.step(c.step(s.step(c.step())))

    plaintext = os.urandom(16)
    enc_data = c.wrap(plaintext, encrypt=False)
    dec_data = s.unwrap(enc_data.data)
    assert dec_data.data == plaintext


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_sspi_no_valid_cred():
    with pytest.raises(InvalidCredentialError, match="No applicable credentials available"):
        spnego._sspi.SSPIProxy(spnego.KerberosKeytab("user_princ", "ccache"), protocol="kerberos")
