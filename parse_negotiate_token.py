#!/usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""
Script that can be used to parse a Negotiate token and output a human readable structure. You can pass in an actual
SPNEGO token or just a raw Kerberos or NTLM token, the script should be smart enough to detect the structure of the
input.
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import argparse
import base64
import json
import os.path
import re
import struct
import sys

from datetime import datetime, timedelta

try:
    import argcomplete
except ImportError:
    argcomplete = None

try:
    from ruamel import yaml
except ImportError:
    yaml = None

PY2 = sys.version_info[0] == 2
if PY2:
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


class ContextFlags:
    DELEGATION = 0
    MUTUAL = 1
    REPLAY = 2
    SEQUENCE = 3
    ANONYMOUS = 4
    CONFIDENTIAL = 5
    INTEGRITY = 6


class MechTypes:
    MS_KRB5 = '1.2.840.48018.1.2.2'
    KRB5 = '1.2.840.113554.1.2.2'
    KRB5_U2U = '1.2.840.113554.1.2.2.3'
    NEGOEX = '1.3.6.1.4.1.311.2.2.30'
    NTLMSSP = '1.3.6.1.4.1.311.2.2.10'
    SPNEGO = '1.3.6.1.5.5.2'


class NegotiateState:
    ACCEPT_COMPLETE = 0
    ACCEPT_INCOMPLETE = 1
    REJECT = 2
    REQUEST_MIC = 3


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
class NtlmNegotiateFlags:
    NTLMSSP_NEGOTIATE_56 = 0x80000000
    NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
    NTLMSSP_NEGOTIATE_128 = 0x20000000
    NTLMSSP_RESERVED_R1 = 0x10000000
    NTLMSSP_RESERVED_R2 = 0x08000000
    NTLMSSP_RESERVED_R3 = 0x04000000
    NTLMSSP_NEGOTIATE_VERSION = 0x02000000
    NTLMSSP_RESERVED_R4 = 0x01000000
    NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
    NTLMSSP_RESERVED_R5 = 0x00200000
    NTLMSSP_NEGOTIATE_IDENTITY = 0x00100000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
    NTLMSSP_RESERVED_R6 = 0x00040000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
    NTLMSSP_RESERVED_R7 = 0x00004000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
    NTLMSSP_ANOYNMOUS = 0x00000800
    NTLMSSP_RESERVED_R8 = 0x00000400
    NTLMSSP_NEGOTIATE_NTLM = 0x00000200
    NTLMSSP_RESERVED_R9 = 0x00000100
    NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
    NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
    NTLMSSP_NEGOTIATE_SEAL = 0x00000020
    NTLMSSP_NEGOTIATE_SIGN = 0x00000010
    NTLMSSP_RESERVED_R10 = 0x00000008
    NTLMSSP_REQUEST_TARGET = 0x00000004
    NTLMSSP_NEGOTIATE_OEM = 0x00000002
    NTLMSSP_NEGOTIATE_UNICODE = 0x00000001


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
class NtlmAvId:
    MSV_AV_EOL = 0x00
    MSV_AV_NB_COMPUTER_NAME = 0x01
    MSV_AV_NB_DOMAIN_NAME = 0x02
    MSV_AV_DNS_COMPUTER_NAME = 0x03
    MSV_AV_DNS_DOMAIN_NAME = 0x04
    MSV_AV_DNS_TREE_NAME = 0x05
    MSV_AV_FLAGS = 0x06
    MSV_AV_TIMESTAMP = 0x07
    MSV_AV_SINGLE_HOST = 0x08
    MSV_AV_TARGET_NAME = 0x09
    MSV_AV_CHANNEL_BINDINGS = 0x0a


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
class NtlmAvFlags:
    AUTHENTICATION_CONSTRAINED = 0x1
    MIC_PROVIDED = 0x2
    UNTRUSTED_SPN_SOURCE = 0x4


# https://tools.ietf.org/html/rfc4120#section-5.5.1 - ap-options
class KerberosAPOptions:
    MUTUAL_REQUIRED = 0x00000020
    USE_SESSION_KEY = 0x00000040
    RESERVED = 0x000000080


# https://ldapwiki.com/wiki/Kerberos%20Encryption%20Types - etypes
class KerberosEncryptionTypes:
    DES_CBC_CRS = 0x0001
    DES_CBC_MD4 = 0x0002
    DES_CBC_MD5 = 0x0003
    DES_CBC_RAW = 0x0004
    DES3_CBC_RAW = 0x0006
    DES3_CBC_SHA1 = 0x0010
    AES128_CTS_HMAC_SHA1_96 = 0x0011
    AES256_CTS_HMAC_SHA1_96 = 0x0012
    AES128_CTS_HMAC_SHA256_128 = 0x0013
    AES256_CTS_HMAC_SHA384_192 = 0x0014
    RC4_HMAC = 0x0017
    RC4_HMAC_EXP = 0x0018
    CAMELLIA128_CTS_CMAC = 0x0019
    CAMELLIA256_CTS_CMAC = 0x001a


# https://tools.ietf.org/html/rfc4120#section-7.5.9
class KerberosErrorCode:
    KDC_ERR_NONE = 0
    KDC_ERR_NAME_EXP = 1
    KDC_ERR_SERVICE_EXP = 2
    KDC_ERR_BAD_PVNO = 3
    KDC_ERR_C_OLD_MAST_KVNO = 4
    KDC_ERR_S_OLD_MAST_KVNO = 5
    KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
    KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
    KDC_ERR_PRINCIPAL_NOT_UNIQUE = 8
    KDC_ERR_NULL_KEY = 9
    KDC_ERR_CANNOT_POSTDATE = 10
    KDC_ERR_NEVER_VALID = 11
    KDC_ERR_POLICY = 12
    KDC_ERR_BADOPTION = 13
    KDC_ERR_ETYPE_NOSUPP = 14
    KDC_ERR_SUMTYPE_NOSUPP = 15
    KDC_ERR_PADATA_TYPE_NOSUPP = 16
    KDC_ERR_TRTYPE_NOSUPP = 17
    KDC_ERR_CLIENT_REVOKED = 18
    KDC_ERR_SERVICE_REVOKED = 19
    KDC_ERR_TGT_REVOKED = 20
    KDC_ERR_CLIENT_NOTYET = 21
    KDC_ERR_SERVICE_NOTYET = 22
    KDC_ERR_KEY_EXPIRED = 23
    KDC_ERR_PREAUTH_FAILED = 24
    KDC_ERR_PREAUTH_REQUIRED = 25
    KDC_ERR_SERVER_NOMATCH = 26
    KDC_ERR_MUST_USE_USER2USER = 27
    KDC_ERR_PATH_NOT_ACCEPTED = 28
    KDC_ERR_SVC_UNAVAILABLE = 29
    KRB_AP_ERR_BAD_INTEGRITY = 31
    KRB_AP_ERR_TKT_EXPIRED = 32
    KRB_AP_ERR_TKT_NYV = 33
    KRB_AP_ERR_REPEAT = 34
    KRB_AP_ERR_NOT_US = 35
    KRB_AP_ERR_BADMATCH = 36
    KRB_AP_ERR_SKEW = 37
    KRB_AP_ERR_BADADDR = 38
    KRB_AP_ERR_BADVERSION = 39
    KRB_AP_ERR_MSG_TYPE = 40
    KRB_AP_ERR_MODIFIED = 41
    KRB_AP_ERR_BADORDER = 42
    KRB_AP_ERR_BADKEYVER = 44
    KRB_AP_ERR_NOKEY = 45
    KRB_AP_ERR_MUT_FAIL = 46
    KRB_AP_ERR_BADDIRECTION = 47
    KRB_AP_ERR_METHOD = 48
    KRB_AP_ERR_BADSEQ = 49
    KRB_AP_ERR_INAPP_CKSUM = 50
    KRB_AP_PATH_NOT_ACCEPTED = 51
    KRB_ERR_RESPONSE_TOO_BIG = 52
    KRB_ERR_GENERIC = 60
    KRB_ERR_FIELD_TOOLONG = 61
    KDC_ERROR_CLIENT_NOT_TRUSTED = 62
    KDC_ERROR_KDC_NOT_TRUSTED = 63
    KDC_ERROR_INVALID_SIG = 64
    KDC_ERR_KEY_TOO_WEAK = 65
    KDC_ERR_CERTIFICATE_MISMATCH = 66
    KRB_AP_ERR_NO_TGT = 67
    KDC_ERR_WRONG_REALM = 68
    KRB_AP_ERR_USER_TO_USER_REQUIRED = 69
    KDC_ERR_CANT_VERIFY_CERTIFICATE = 70
    KDC_ERR_INVALID_CERTIFICATE = 71
    KDC_ERR_REVOKED_CERTIFICATE = 72
    KDC_ERR_REVOCATION_STATUS_UNKNOWN = 73
    KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74
    KDC_ERR_CLIENT_NAME_MISMATCH = 75
    KDC_ERR_KDC_NAME_MISMATCH = 76


# https://tools.ietf.org/html/rfc4120#section-5.10
class KerberosMessageTypes:
    AS_REQ = 10
    AS_REP = 11
    TGS_REQ = 12
    TGS_REP = 13
    AP_REQ = 14
    AP_REP = 15
    KERB_ERROR = 30


# https://tools.ietf.org/html/rfc4120#section-5.2.7 - padata-value
class KerberosPADataType:
    TGS_REQ = 1
    ENC_TIMESTAMP = 2
    PW_SALT = 3
    ETYPE_INFO = 11
    ETYPE_INFO2 = 19


# https://tools.ietf.org/html/rfc4120#section-6.2
class KerberosPrincipalNameType:
    NT_UNKNOWN = 0
    NT_PRINCIPAL = 1
    NT_SRV_INST = 2
    NT_SRV_HST = 3
    NT_SRV_XHST = 4
    NT_UID = 5
    NT_X500_PRICNIPAL = 6
    NT_SMTP_NAME = 7
    NT_ENTERPRISE = 10


class Application:

    def __init__(self, value, tag_number):
        self.value = value
        self.tag_number = tag_number


class ContextSpecific:

    def __init__(self, value, tag_number):
        self.value = value
        self.tag_number = tag_number


def _to_bytes(obj, encoding='utf-8'):
    if isinstance(obj, binary_type):
        return obj
    elif isinstance(obj, text_type):
        return obj.encode(encoding)
    else:
        return _to_bytes(str(text_type), encoding=encoding)


def _to_text(obj, encoding='utf-8'):
    if isinstance(obj, text_type):
        return obj
    elif isinstance(obj, binary_type):
        return obj.decode(encoding)
    else:
        return _to_text(str(obj), encoding=encoding)


if PY2:
    _to_native = _to_bytes
else:
    _to_native = _to_text


def _get_flag_ids(value, enum_class):
    flags = []
    for k, v in dict(vars(enum_class)).items():
        if k.startswith('__'):
            continue

        if value & v == v:
            value &= ~v
            flags.append("%s (%d)" % (k, v))

    if value != 0:
        flags.append("UNKNOWN (%d)" % value)

    return flags


def _get_enum_id(value, enum_class):
    enum_name = 'UNKNOWN'

    for k, v in dict(vars(enum_class)).items():
        if k.startswith('__'):
            continue

        if value == v:
            enum_name = k
            break

    return "%s (%s)" % (enum_name, value)


def _filetime_to_datetime(filetime):
    epoch_filetime = 116444736000000000  # EPOCH representing in filetime (100 nanoseconds since 1601-01-01
    epoch_time_ms = (filetime - epoch_filetime) / 10
    return datetime(1970, 1, 1) + timedelta(microseconds=epoch_time_ms)


def _to_bits(b):
    if isinstance(b, bytes):
        int_value = struct.unpack('b', b[:1])[0]
    else:
        int_value = b

    bits = str(bin(int_value))[2:].zfill(8)
    return " ".join([bits[i:i + 4] for i in range(0, len(bits), 4)])


def _unpack_asn_integer(b_data, length):
    if length == 1:
        value = struct.unpack("B", b_data[:1])[0]
        is_negative = bool(value & 0b10000000)
    else:
        # If multiple bytes are used and the value is positive even with the leading byte, the first octet
        # will be 0
        is_negative = False
        value = 0
        idx = 0
        while idx != length:
            element = struct.unpack("B", b_data[idx:idx + 1])[0]

            # When multiple bytes are used and the leading byte is 0, the value is a positive number.
            if idx == 0 and element == 0:
                idx += 1
                continue

            if idx == 0 and element & 0b10000000:
                is_negative = True
                element &= 0b01111111

            value = (value << 8) + value

            idx += 1

    if is_negative:
        value *= -1

    return value


def _unpack_asn_octet_number(b_data):
    # Some ASN.1 fields contain an number that can be encoded over 1 or more octets. The highest bit is set when
    # another octet is required. This bit is then discarded and the bits over all octets are combined together to make
    # the number required.
    i = 0
    idx = 0
    while True:
        element = struct.unpack("B", b_data[idx:idx+1])[0]
        idx += 1

        # Shift the bits left by 7 (8 (was in a higher octet) - 1 (remove highest bit for more octets required)) and
        # add the current value sans the highest bit. Keep on doing this until no more octets are required.
        i = (i << 7) + (element & 0b01111111)
        if not element & 0b10000000:
            break

    # The caller probably wants to know how many octets were used to serialize the number.
    return i, idx


def _parse_asn1(b_data):
    """Poor mans ASN.1 parser so we don't have to rely on extra libraries."""
    tag_class = (struct.unpack('B', b_data[:1])[0] & 0b11000000) >> 6
    # is_constructed = bool(struct.unpack('B', b_data[:1])[0] & 0b00100000)
    tag_number = struct.unpack('B', b_data[:1])[0] & 0b00011111

    length_offset = 1
    if tag_number == 31:
        # Tag is in long form, need to decode the next octet(s) until we get the full tag number.
        tag_number, octet_count = _unpack_asn_octet_number(b_data[1:])
        length_offset += octet_count

    length = struct.unpack('B', b_data[length_offset:length_offset + 1])[0]
    if length & 0b10000000:
        length_octets = length & 0b01111111
        length = 0

        if length_octets == 0:
            # Indefinite form, length ends at the next end-of-content octets (b"\x00\x00")
            length = b_data[length_offset + 1:].index(b"\x00\x00")
        else:
            # Definite long form, bit 7-1 of the original octet contains the number of octets that is the length.
            for octet_idx in range(1, length_octets + 1):
                octet_val = struct.unpack('B', b_data[length_offset + octet_idx:length_offset + octet_idx + 1])[0]
                length += octet_val << (8 * (length_octets - octet_idx))
    else:
        # Definite short form, the length is the bit 7-1 of the original octet.
        length_octets = 0
        length &= 0b01111111

    data_offset = length_offset + length_octets + 1

    if length == 0:
        return b_data[:data_offset], b_data[data_offset:]

    b_data = b_data[data_offset:]
    if tag_class == 0:  # Universal
        b_value = b_data[:length]
        value = b_value

        if tag_class == 0:  # Universal
            if tag_number == 1:  # BOOLEAN
                value = b_value != b"\x00" * length
            elif tag_number == 2:  # INTEGER
                value = _unpack_asn_integer(b_value, length)
            elif tag_number == 3:  # BIT_STRING
                if length > 1:
                    # First octet is the number of unused bits we need to make sure we clear
                    unused_bits = struct.unpack("B", b_value[:1])[0]

                    last_element = struct.unpack("B", b_value[length - 1:length])[0]
                    last_element = (last_element >> unused_bits) << unused_bits

                    value = b_value[1:-1] + struct.pack("B", last_element)
                else:
                    value = b""
            elif tag_number == 4:  # OCTET STRING
                pass  # The raw byte string is what we want here.
            elif tag_number == 6:  # OBJECT IDENTIFIER
                # The first 2 ids in an OID is contained in the first byte as '(X * 40) + Y'
                first_element = struct.unpack("B", b_value[:1])[0]
                second_element = first_element % 40
                ids = [(first_element - second_element) // 40, second_element]

                # The remaining OID fields are encoded like a long form tag id.
                idx = 1
                while idx != len(b_value):
                    id, octet_len = _unpack_asn_octet_number(b_value[idx:])
                    ids.append(id)
                    idx += octet_len

                value = ".".join([str(i) for i in ids])
            elif tag_number == 10:  # ENUMERATED
                value = _unpack_asn_integer(b_value, length)
            elif tag_number == 16:  # SEQUENCE and SEQUENCE OF
                value = []
                while b_value:
                    v, b_value = _parse_asn1(b_value)
                    value.append(v)

                # If all the elements have a tag number then convert to a dict (not SEQUENCE OF)
                is_sequence = all(hasattr(v, 'tag_number') for v in value)
                if is_sequence:
                    value = dict((v.tag_number, v.value) for v in value)
            elif tag_number == 24:  # GeneralizedTime
                try:
                    value = datetime.strptime(_to_text(b_value), '%Y%m%d%H%M%S.%f%z')
                except ValueError:
                    value = datetime.strptime(_to_text(b_value), '%Y%m%d%H%M%S%z')
            elif tag_number == 27:  # GeneralString
                pass  # The raw byte string is what we want here.
            else:
                raise NotImplementedError("Not implement tag number %d" % tag_number)
    elif tag_class == 1:  # Application
        values = []
        while b_data:
            v, b_data = _parse_asn1(b_data)
            values.append(v)

        # This could be an implicit tag where we don't know the type of the tag.
        value = Application(values if len(values) > 1 else values[0], tag_number)
    elif tag_class == 2:  # Context-specific
        v, _ = _parse_asn1(b_data)
        value = ContextSpecific(v, tag_number)
    else:
        raise NotImplementedError("Not implement tag class %d" % tag_number)

    return value, b_data[length:]


def _parse_kerberos_enc_data(raw_data, b_secret=None):
    data = {
        'etype': _get_enum_id(raw_data[0], KerberosEncryptionTypes),
        'etype_raw': raw_data[0],
        'kvno': raw_data.get(1, None),
        'cipher': _to_text(base64.b16encode(raw_data[2])),
    }

    if b_secret:
        raise NotImplementedError()
        # Would love to be able to do this but it's probably a bit more than I chew right now
        #if raw_data[0] == KerberosEncryptionTypes.AES256_CTS_HMAC_SHA1_96:
        #    from cryptography.hazmat.backends import default_backend
        #    from cryptography.hazmat.primitives import hashes
        #    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        #
        #    # tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength))
        #    # key = DK(tkey, "kerberos")
        #    # (iterations,) = unpack('>L', params or b'\x00\x00\x10\x00')
        #    iterations = struct.unpack(">I", b"\x00\x00\x10\x00")[0]
        #
        #    hkdf = PBKDF2HMAC(
        #        algorithm=hashes.SHA1(),
        #        length=16,  # 32
        #        salt=b"ATHENA.MIT.EDUraeburn",
        #        iterations=1,
        #        backend=default_backend(),
        #    )
        #    tkey = hkdf.derive(b"password")
        #    a = base64.b16encode(tkey)  # cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
        #
        #    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        #    c = Cipher(algorithms.AES(tkey), modes.CBC(b"\x00" * 16), default_backend()).encryptor()
        #    key = c.update(b"kerberos".zfill(16)) + c.finalize()
        #    b = base64.b16encode(key)  # 42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15 - AES key
        #
        #    # ciphertext output is the concatenation of the output of E and a (possibly truncated) HMAC using the
        #    # specified hash function H (SHA1), both applied to the plaintext with a random confounder prefix and
        #    # sufficient padding to bring it to a multiple of the message block size. When HMAC is computed the key is
        #    # used in the protocol key form.
        #    a = ''
        #else:
        #    raise NotImplementedError("Cannot decrypt encryption type '%s'" % data['etype'])

    return data


def _parse_kerberos_principal_name(raw_data, encoding):
    if not raw_data:
        return None

    return {
        'name-type': _get_enum_id(raw_data[0], KerberosPrincipalNameType),
        'name-type_raw': raw_data[0],
        'name-string': [_to_text(b, encoding=encoding) for b in raw_data[1]],
    }


def _parse_kerberos_as_req(raw_data, encoding):
    padata = []
    for data in raw_data[3]:
        value = _to_text(base64.b16encode(data[2])),
        if data[1] == KerberosPADataType.ENC_TIMESTAMP:
            enc_timestamp = _parse_asn1(data[2])[0]
            value = _parse_kerberos_enc_data(enc_timestamp)
        elif data[1] == KerberosPADataType.TGS_REQ:
            a = ''

        padata.append({
            'padata-type': _get_enum_id(data[1], KerberosPADataType),
            'padata-type_raw': data[1],
            'padata-value': value,
        })

    msg = {
        'pvno': raw_data[1],
        'msg-type': _get_enum_id(raw_data[2], KerberosMessageTypes),
        'padata': padata,
        'req-body': None,
    }
    return msg


def _parse_kerberos_ap_req(raw_data, encoding):
    """
    RFC 4120

    AP-REQ          ::= [APPLICATION 14] SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (14),
        ap-options      [2] APOptions,
        ticket          [3] Ticket,
        authenticator   [4] EncryptedData -- Authenticator
    }
    """
    ap_options = struct.unpack("<I", raw_data[2])[0]

    raw_ticket = raw_data[3].value[0]
    ticket = {
        'tkt-vno': raw_ticket[0],
        'realm': _to_text(raw_ticket[1], encoding=encoding),
        'sname': _parse_kerberos_principal_name(raw_ticket[2], encoding),
        'enc-part': _parse_kerberos_enc_data(raw_ticket[3]),
    }

    msg = {
        'pvno': raw_data[0],
        'msg-type': _get_enum_id(raw_data[1], KerberosMessageTypes),
        'msg-type_raw': raw_data[1],
        'ap-options': _get_flag_ids(ap_options, KerberosAPOptions),
        'ap-options_raw': ap_options,
        'ticket': ticket,
        'authenticator': _parse_kerberos_enc_data(raw_data[4]),
    }
    return msg


def _parse_kerberos_ap_rep(raw_data, encoding):
    """
    RFC 4120

    AS-REQ          ::= [APPLICATION 10] KDC-REQ

    KDC-REQ         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        pvno            [1] INTEGER (5) ,
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                            -- NOTE: not empty --,
        req-body        [4] KDC-REQ-BODY
    }
    """
    msg = {
        'pvno': raw_data[0],
        'msg-type': _get_enum_id(raw_data[1], KerberosMessageTypes),
        'msg-type_raw': raw_data[1],
        'enc-part': _parse_kerberos_enc_data(raw_data[2]),
    }
    return msg


def _parse_kerberos_krb_error(raw_data, encoding):
    """
    RFC 4120

    KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (30),
        ctime           [2] KerberosTime OPTIONAL,
        cusec           [3] Microseconds OPTIONAL,
        stime           [4] KerberosTime,
        susec           [5] Microseconds,
        error-code      [6] Int32,
        crealm          [7] Realm OPTIONAL,
        cname           [8] PrincipalName OPTIONAL,
        realm           [9] Realm -- service realm --,
        sname           [10] PrincipalName -- service name --,
        e-text          [11] KerberosString OPTIONAL,
        e-data          [12] OCTET STRING OPTIONAL
    }
    """
    msg = {
        'pvno': raw_data[0],
        'msg-type': _get_enum_id(raw_data[1], KerberosMessageTypes),
        'msg-type_raw': raw_data[1],
        'ctime': raw_data[2].isoformat() if 2 in raw_data else None,
        'cusec': raw_data.get(3, None),
        'stime': raw_data[4].isoformat(),
        'susec': raw_data[5],
        'error-code': _get_enum_id(raw_data[6], KerberosErrorCode),
        'error-code_raw': raw_data[6],
        'crealm': _to_text(raw_data[7], encoding=encoding) if 7 in raw_data else None,
        'cname': _parse_kerberos_principal_name(raw_data.get(8, None), encoding),
        'realm': _to_text(raw_data[9], encoding=encoding),
        'sname': _parse_kerberos_principal_name(raw_data[10], encoding),
        'e-text': _to_text(raw_data[11], encoding=encoding) if 11 in raw_data else None,
        'e-data': _to_text(base64.b16encode(raw_data[12])) if 12 in raw_data else None,
    }
    return msg


def _parse_ntlm_version(b_data):
    return {
        'Major': struct.unpack("<B", b_data[:1])[0],
        'Minor': struct.unpack("<B", b_data[1:2])[0],
        'Build': struct.unpack("<H", b_data[2:4])[0],
        'NTLMRevision': struct.unpack("<B", b_data[7:8])[0],
    }


def _parse_ntlm_target_info(b_data):
    info = []

    av_id = -1
    while av_id != NtlmAvId.MSV_AV_EOL:
        av_id = struct.unpack("<H", b_data[0:2])[0]
        av_len = struct.unpack("<H", b_data[2:4])[0]
        b_av_value = b_data[4:av_len + 4]

        unicode_values = [NtlmAvId.MSV_AV_NB_COMPUTER_NAME, NtlmAvId.MSV_AV_NB_DOMAIN_NAME,
                          NtlmAvId.MSV_AV_DNS_COMPUTER_NAME, NtlmAvId.MSV_AV_DNS_DOMAIN_NAME,
                          NtlmAvId.MSV_AV_DNS_TREE_NAME, NtlmAvId.MSV_AV_TARGET_NAME]

        if av_id == NtlmAvId.MSV_AV_EOL:
            av_value = None
        elif av_id in unicode_values:
            av_value = b_av_value.decode('utf-16-le')
        elif av_id == NtlmAvId.MSV_AV_FLAGS:
            av_value = _get_flag_ids(struct.unpack("<I", b_av_value)[0], NtlmAvFlags)
        elif av_id == NtlmAvId.MSV_AV_TIMESTAMP:
            filetime = struct.unpack("<Q", b_av_value)[0]
            av_value = _filetime_to_datetime(filetime).isoformat()
        elif av_id == NtlmAvId.MSV_AV_SINGLE_HOST:
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b
            av_value = {
                'Size': struct.unpack("<I", b_av_value[:4])[0],
                'Z4': _to_text(base64.b16encode(b_av_value[4:8])),
                'CustomData': _to_text(base64.b16encode(b_av_value[8:12])),
                'MachineID': _to_text(base64.b16encode(b_av_value[12:44])),
            }
        else:
            # We shouldn't hit this but just in case
            av_value = _to_text(base64.b16encode(b_av_value))

        info.append({
            'AvId': _get_enum_id(av_id, NtlmAvId),
            'Value': av_value
        })
        b_data = b_data[av_len + 4:]

    return info


def _parse_ntlm_negotiate(b_data, oem_cp):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
    flags = struct.unpack("<I", b_data[12:16])[0]

    msg = {
        'NegotiateFlagsRaw': flags,
        'NegotiateFlags': _get_flag_ids(flags, NtlmNegotiateFlags),
        'DomainName': None,
        'Workstation': None,
        'Version': None,
    }

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_VERSION != 0:
        msg['Version'] = _parse_ntlm_version(b_data[32:40])

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED != 0:
        domain_name_len = struct.unpack("<H", b_data[16:18])[0]
        domain_name_offset = struct.unpack("<I", b_data[20:24])[0]

        msg['DomainName'] = b_data[domain_name_offset:domain_name_offset + domain_name_len].decode(oem_cp)

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED != 0:
        workstation_len = struct.unpack("<H", b_data[24:26])[0]
        workstation_offset = struct.unpack("<I", b_data[28:32])[0]
        msg['Workstation'] = b_data[workstation_offset:workstation_offset + workstation_len].decode(oem_cp)

    return msg


def _parse_ntlm_challenge(b_data, oem_cp):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
    flags = struct.unpack("<I", b_data[20:24])[0]

    msg = {
        'NegotiateFlagsRaw': flags,
        'NegotiateFlags': _get_flag_ids(flags, NtlmNegotiateFlags),
        'TargetName': None,
        'ServerChallenge': _to_text(base64.b16encode(b_data[24:32])),
        'Reserved': _to_text(base64.b16encode(b_data[32:40])),
        'TargetInfo': None,
        'Version': None,
    }

    encoding = 'utf-16-le' if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE != 0 else oem_cp
    if flags & NtlmNegotiateFlags.NTLMSSP_REQUEST_TARGET != 0:
        target_name_len = struct.unpack("<H", b_data[12:14])[0]
        target_name_offset = struct.unpack("<I", b_data[16:20])[0]
        msg['TargetName'] = b_data[target_name_offset:target_name_offset + target_name_len].decode(encoding)

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO != 0:
        target_info_len = struct.unpack("<H", b_data[40:42])[0]
        target_info_offset = struct.unpack("<I", b_data[44:48])[0]
        b_target_info = b_data[target_info_offset:target_info_offset + target_info_len]
        msg['TargetInfo'] = _parse_ntlm_target_info(b_target_info)

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_VERSION != 0:
        msg['Version'] = _parse_ntlm_version(b_data[48:56])

    return msg


def _parse_ntlm_authenticate(b_data, oem_cp):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
    flags = struct.unpack("<I", b_data[60:64])[0]

    msg = {
        'NegotiateFlagsRaw': flags,
        'NegotiateFlags': _get_flag_ids(flags, NtlmNegotiateFlags),
        'LmChallengeResponse': None,
        'NtChallengeResponse': None,
        'DomainName': None,
        'UserName': None,
        'Workstation': None,
        'EncryptedRandomSessionKey': None,
        'Version': None,
        'MIC': _to_text(base64.b16encode(b_data[72:88])),
    }

    encoding = 'utf-16-le' if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE != 0 else oem_cp

    lm_challenge_len = struct.unpack("<H", b_data[12:14])[0]
    if lm_challenge_len != 0:
        lm_challenge_offset = struct.unpack("<I", b_data[16:20])[0]
        lm_challenge_end = lm_challenge_offset + lm_challenge_len

        lm_response = {
            'ResponseType': None,
            'LMProofStr': None,
        }
        lm_response_data = b_data[lm_challenge_offset:lm_challenge_end]

        if len(lm_response_data) == 24:
            lm_response['ResponseType'] = 'LMv1'
            lm_response['LMProofStr'] = _to_text(base64.b16encode(lm_response_data)),
        else:
            lm_response['ResponseType'] = 'LMv2'
            lm_response['LMProofStr'] = _to_text(base64.b16encode(lm_response_data[:16])),
            lm_response['ChallengeFromClient'] = _to_text(base64.b16encode(lm_response_data[16:])),

    nt_challenge_len = struct.unpack("<H", b_data[20:22])[0]
    if nt_challenge_len != 0:
        nt_challenge_offset = struct.unpack("<I", b_data[24:28])[0]
        nt_challenge_end = nt_challenge_offset + nt_challenge_len

        nt_response = {
            'ResponseType': None,
            'NTProofStr': None,
        }
        nt_response_data = b_data[nt_challenge_offset:nt_challenge_end]

        if len(nt_response_data) == 24:
            nt_response['ResponseType'] = 'NTLMv1'
            nt_response['NTProofStr'] = _to_text(base64.b16encode(nt_response_data)),
        else:
            nt_response['ResponseType'] = 'NTLMv2'
            nt_response['NTProofStr'] = _to_text(base64.b16encode(nt_response_data[:16])),

            b_challenge = nt_response_data[16:]
            client_challenge = {
                'RespType': struct.unpack("<B", b_challenge[:1])[0],
                'HiRespType': struct.unpack("<B", b_challenge[1:2])[0],
                'Reserved1': struct.unpack("<H", b_challenge[2:4])[0],
                'Reserved2': struct.unpack("<I", b_challenge[4:8])[0],
                'TimeStamp': _filetime_to_datetime(struct.unpack("<Q", b_challenge[8:16])[0]).isoformat(),
                'ChallengeFromClient': _to_text(base64.b16encode(b_challenge[16:24])),
                'Reserved3': struct.unpack("<I", b_challenge[24:28])[0],
                'AvPairs': _parse_ntlm_target_info(b_challenge[28:]),
            }
            nt_response['ClientChallenge'] = client_challenge

        msg['NtChallengeResponse'] = nt_response

    domain_len = struct.unpack("<H", b_data[28:30])[0]
    if domain_len != 0:
        domain_offset = struct.unpack("<I", b_data[32:36])[0]
        domain_end = domain_offset + domain_len
        msg['DomainName'] = b_data[domain_offset:domain_end].decode(encoding)

    user_len = struct.unpack("<H", b_data[36:38])[0]
    if user_len != 0:
        user_offset = struct.unpack("<I", b_data[40:44])[0]
        user_end = user_offset + user_len
        msg['UserName'] = b_data[user_offset:user_end].decode(encoding)

    workstation_len = struct.unpack("<H", b_data[44:46])[0]
    if workstation_len != 0:
        workstation_offset = struct.unpack("<I", b_data[48:52])[0]
        workstation_end = workstation_offset + workstation_len
        msg['Workstation'] = b_data[workstation_offset:workstation_end].decode(encoding)

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH != 0:
        key_len = struct.unpack("<H", b_data[52:54])[0]
        key_offset = struct.unpack("<I", b_data[56:60])[0]
        msg['EncryptedRandomSessionKey'] = _to_text(base64.b16encode(b_data[key_offset:key_offset + key_len]))

    if flags & NtlmNegotiateFlags.NTLMSSP_NEGOTIATE_VERSION != 0:
        msg['Version'] = _parse_ntlm_version(b_data[64:72])

    return msg


def _parse_spnego_init(raw_data, encoding=None):
    """
    Parses a NegTokenInit ASN.1 structure.

    RFC 4178
    NegTokenInit ::= SEQUENCE {
        mechTypes       [0] MechTypeList,
        reqFlags        [1] ContextFlags  OPTIONAL,
        -- inherited from RFC 2478 for backward compatibility,
        -- RECOMMENDED to be left out
        mechToken       [2] OCTET STRING  OPTIONAL,
        mechListMIC     [3] OCTET STRING  OPTIONAL,
        ...
    }
    """
    mech_token = None
    if 2 in raw_data:
        try:
            mech_token = parse_token(raw_data[2], encoding=encoding)
        except Exception as e:
            mech_token = {
                'MessageType': 'Unknown - Failed to parse see Data for more details.',
                'Data': 'Failed to parse SPNEGO token: %s' % _to_native(e),
                'RawData': _to_text(base64.b16encode(raw_data[2])),
            }

    msg = {
        'mechTypes': [_get_enum_id(m, MechTypes) for m in raw_data[0]],
        'reqFlags': _get_flag_ids(struct.unpack("<I", raw_data[1])[0], ContextFlags) if 1 in raw_data else None,
        'reqFlags_raw': struct.unpack("<I", raw_data[1])[0] if 1 in raw_data else None,
        'mechToken': mech_token,
        'mechListMIC': _to_text(base64.b16encode(raw_data[3])) if 3 in raw_data else None,
    }
    return msg


def _parse_spnego_resp(raw_data, encoding=None):
    response_token = None
    if 2 in raw_data:
        try:
            response_token = parse_token(raw_data[2], encoding=encoding)
        except Exception as e:
            response_token = {
                'MessageType': 'Unknown - Failed to parse see Data for more details.',
                'Data': 'Failed to parse SPNEGO token: %s' % _to_native(e),
                'RawData': _to_text(base64.b16encode(raw_data[2])),
            }

    msg = {
        'negState': _get_enum_id(raw_data[0], NegotiateState),
        'negstate_raw': raw_data[0],
        'supportedMech': _get_enum_id(raw_data[1], MechTypes) if 1 in raw_data else None,
        'responseToken': response_token,
        'mechListMIC': _to_text(base64.b16encode(raw_data[3])) if 3 in raw_data else None,
    }
    return msg


def main():
    """Main program entry point."""
    args = parse_args()

    if args.token:
        b_data = base64.b64decode(args.token)
    else:
        if args.file:
            file_path = os.path.abspath(os.path.expanduser(os.path.expandvars(args.file)))
            b_file_path = _to_bytes(file_path)
            if not os.path.exists(b_file_path):
                raise ValueError("Cannot find file at path '%s'" % _to_native(b_file_path))

            with open(b_file_path, mode='rb') as fd:
                b_data = fd.read()
        else:
            b_data = sys.stdin.buffer.read()

        if re.match(b'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', b_data):
            b_data = base64.b64decode(b_data.strip())

    token_info = parse_token(b_data, encoding=args.encoding)

    if args.output_format == 'yaml':
        y = yaml.YAML()
        y.default_flow_style = False
        y.dump(token_info, sys.stdout)
    else:
        print(json.dumps(token_info, indent=4))


def parse_args():
    """Parse and return args."""
    parser = argparse.ArgumentParser(description='Parse Microsoft authentication tokens into a human readable format.')

    data = parser.add_mutually_exclusive_group()

    data.add_argument('-t', '--token',
                      dest='token',
                      help='Raw base64 encoded token as a command line argument.')

    data.add_argument('-f', '--file',
                      default='',
                      dest='file',
                      help='Path to file that contains raw bytes or base64 string of token to parse, Defaults to '
                           'reading from stdin.')

    parser.add_argument('--encoding',
                        dest='encoding',
                        help="The encoding to use when trying to decode text fields from bytes in tokens that don't "
                             "have a negotiated encoding. This defaults to 'windows-1252' for NTLM tokens and 'utf-8' "
                             "for Kerberos/SPNEGO tokens.")

    parser.add_argument('--format', '--output-format',
                        choices=['json', 'yaml'],
                        default='json',
                        dest='output_format',
                        type=lambda s: s.lower(),
                        help='Set the output format of the token, default is (json).')

    if argcomplete:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.output_format == 'yaml' and not yaml:
        raise ValueError('Cannot output as yaml as ruamel.yaml is not installed.')

    return args


def parse_token(b_data, encoding=None):
    """
    :param b_data: A byte string of the token to parse. This can be a NTLM or GSSAPI (SPNEGO/Kerberos) token.
    :param encoding: The encoding to use for token fields that represent text. This is only used for fields where there
        is no negotiation for the encoding of that particular field. Defaults to 'windows-1252' for NTLM and 'utf-8'
        for Kerberos.
    :return: A dict containing the parsed token data.
    """
    if b_data.startswith(b'NTLMSSP\x00'):
        token_info = parse_ntlm_message(b_data, oem_cp=encoding)
    else:
        token_info = parse_gssapi_message(b_data, encoding=encoding)

    return token_info


def parse_gssapi_message(b_data, encoding=None):
    """
    Parse a GSSAPI token and return a dict containing the structured values for easier parsing. The values inside the
    'Data' key are dynamic and are based on the MessageType that is being parsed.

    :param b_data: A byte string of the GSSAPI token to parse.
    :param encoding: The encoding to use for KerberosString values as the encoding is not part of the token data.
        Defaults to utf-8.
    :return: A dict containing the parsed GSSAPI message.
    """
    raw_data = _parse_asn1(b_data)[0]

    # RFC 2743
    # InitialContextToken ::=
    # -- option indication (delegation, etc.) indicated within
    # -- mechanism-specific token
    # [APPLICATION 0] IMPLICIT SEQUENCE {
    #         thisMech MechType,
    #         innerContextToken ANY DEFINED BY thisMech
    #            -- contents mechanism-specific
    #            -- ASN.1 structure not required
    #         }
    if isinstance(raw_data, Application) and isinstance(raw_data.value, list) and raw_data.tag_number == 0:
        mech_type = raw_data.value[0]
        if mech_type in [MechTypes.MS_KRB5, MechTypes.KRB5]:
            # Kerberos defines 4 bytes after the mech type to denote the message type. This info is already contained
            # in the data so we just ignore it here.
            raw_data = raw_data.value[2]
        else:
            raw_data = raw_data.value[1]
    elif isinstance(raw_data, ContextSpecific) and raw_data.tag_number == 1:
        # Subsequent SPNEGO tokens aren't wrapped in the InitialContextToken structure and are just sent as the
        # innerContextToken. So this check sees if the value is a ContextSpecific structure with a tag of [1] as
        # expected by a SPNEGO negTokenResp
        mech_type = MechTypes.SPNEGO
    else:
        raise ValueError("Token was not a GSSAPI InitialContextToken as defined in RFC 2743.")

    if mech_type in [MechTypes.MS_KRB5, MechTypes.KRB5]:
        if not encoding:
            encoding = 'utf-8'

        # The raw_data at this point is the [APPLICATION {num}] Message of the Kerberos ticket, we use the explicit
        # tag number to determine the message type.
        if raw_data.tag_number == KerberosMessageTypes.AS_REQ:
            raise NotImplementedError()
            #data = _parse_kerberos_as_req(raw_data, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.AS_REP:
            raise NotImplementedError()
            #data = _parse_kerberos_as_rep(raw_data, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.TGS_REQ:
            raise NotImplementedError()
            #data = _parse_kerberos_tgs_req(raw_data, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.TGS_REP:
            raise NotImplementedError()
            #data = _parse_kerberos_tgs_rep(raw_data, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.AP_REQ:
            data = _parse_kerberos_ap_req(raw_data.value, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.AP_REP:
            data = _parse_kerberos_ap_rep(raw_data.value, encoding)
        elif raw_data.tag_number == KerberosMessageTypes.KERB_ERROR:
            data = _parse_kerberos_krb_error(raw_data.value, encoding)
        else:
            raise NotImplementedError("Cannot decode Kerberos message type '%s'" % raw_data.tag_number)

        message_type = _get_enum_id(raw_data.tag_number, KerberosMessageTypes)
    elif mech_type == MechTypes.SPNEGO:
        # RFC 4178
        # NegotiationToken ::= CHOICE {
        #     negTokenInit    [0] NegTokenInit,
        #     negTokenResp    [1] NegTokenResp
        # }
        if raw_data.tag_number == 0:
            message_type = 'SPNEGO NegTokenInit'
            data = _parse_spnego_init(raw_data.value, encoding)
        elif raw_data.tag_number == 1:
            message_type = 'SPNEGO NegTokenResp'
            data = _parse_spnego_resp(raw_data.value, encoding)
        else:
            raise ValueError("Unknown SPNEGO token choice %d" % raw_data.tag_number)
    else:
        raise ValueError("Unknown OID mech type '%s'" % mech_type)

    msg = {
        'MessageType': '%s - %s' % (message_type, _get_enum_id(mech_type, MechTypes)),
        'Data': data,
        'RawData': _to_text(base64.b16encode(b_data)),
    }
    return msg


def parse_ntlm_message(b_data, oem_cp=None):
    """
    Parse an NTLM token and return a dict containing the structured values for easier parsing. The values inside the
    'Data' key are dynamic and are based on the MessageType that is being parsed.

    :param b_data: A byte string of the NTLM token to parse.
    :param oem_cp: Override the OEM codepage for NTLM messages that are not Unicode aware.
    :return: A dict containing the parsed NTLM message.
    """
    if not oem_cp:
        oem_cp = 'windows-1252'

    message_type = struct.unpack("<I", b_data[8:12])[0]
    if message_type == 1:
        message_type_name = "NtlmNegotiate"
        parse_func = _parse_ntlm_negotiate
    elif message_type == 2:
        message_type_name = "NtlmChallenge"
        parse_func = _parse_ntlm_challenge
    else:
        message_type_name = "NtlmAuthenticate"
        parse_func = _parse_ntlm_authenticate

    msg = {
        'MessageType': "%s (%d)" % (message_type_name, message_type),
        'Signature': _to_text(b_data[0:8], encoding='ascii'),
        'Data': parse_func(b_data, oem_cp),
        'RawData': _to_text(base64.b16encode(b_data)),
    }
    return msg


if __name__ == '__main__':
    main()
