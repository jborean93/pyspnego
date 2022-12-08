# -*- coding: utf-8 -*-
# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
import typing

import pytest

import spnego._tls_struct as tls


@pytest.mark.parametrize(
    "enum_cls, value, expected",
    [
        (tls.TlsProtocolVersion, 0x0A, "Unknown TLS Protocol Version 0x000A"),
        (tls.TlsContentType, 0x63, "Unknown TLS Content Type 0x63"),
        (tls.TlsHandshakeMessageType, 0xFF, "Unknown Handshake Message Type 0xFF"),
        (tls.TlsCipherSuite, 0xFF01, "Unknown Cipher Suite 0xFF01"),
        (tls.TlsCompressionMethod, 0x05, "Unknown Compression Method 0x05"),
        (tls.TlsExtensionType, 0x63, "Unknown Extension Type 0x0063"),
        (tls.TlsServerNameType, 2, "Unknown Server Name Type 0x02"),
        (tls.TlsECPointFormat, 3, "Unknown EC Point Format 0x03"),
        (tls.TlsSupportedGroup, 0x1254, "Unknown Supported Group 0x1254"),
        (tls.TlsSignatureScheme, 0x0001, "Unknown Signature Scheme 0x0001"),
        (tls.TlsPskKeyExchangeMode, 0x44, "Unknown PSK Key Exchange Mode 0x44"),
        (tls.TlsECCurveType, 0x55, "Unknown EC Curve Type 0x55"),
        (tls.TlsClientCertificateType, 0x70, "Unknown Client Certificate Type 0x70"),
        (tls.DistinguishedNameType, "1.2.3.4", "Unknown DN OID Type 1.2.3.4"),
    ],
)
def test_tls_enum_missing_member(enum_cls, value, expected):
    actual = enum_cls(value)
    assert isinstance(actual, enum_cls)
    assert actual.name == expected
    assert actual.value == value


def test_tls_enum_fail_non_int():
    with pytest.raises(ValueError, match="'fail' is not a valid TlsProtocolVersion"):
        tls.TlsProtocolVersion("fail")  # type: ignore[arg-type] # Testing a failure here
