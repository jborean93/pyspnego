# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import datetime

import spnego._kerberos as kerb
import spnego._spnego as sp
from spnego._asn1 import (
    TagClass,
    TypeTagNumber,
    pack_asn1,
    pack_asn1_bit_string,
    pack_asn1_general_string,
    pack_asn1_integer,
    pack_asn1_octet_string,
    pack_asn1_sequence,
)
from spnego._context import GSSMech

from .conftest import get_data


def test_parse_enum_unknown():
    actual = kerb.parse_enum(10, enum_type=kerb.KerberosAPOptions)
    assert actual == "UNKNOWN (10)"


def test_parse_flags_unknown():
    actual = kerb.parse_flags(10, enum_type=kerb.KerberosAPOptions)
    assert actual["raw"] == 10
    assert actual["flags"] == ["UNKNOWN (10)"]


def test_kerberos_ap_options_native_labels():
    actual = kerb.KerberosAPOptions.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosAPOptions.mutual_required] == "mutual-required"


def test_kerberos_kdc_options_native_labels():
    actual = kerb.KerberosKDCOptions.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosKDCOptions.forwardable] == "forwardable"


def test_kerberos_encryption_type_native_labels():
    actual = kerb.KerberosEncryptionType.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosEncryptionType.des_cbc_crc] == "DES_CBC_CRC"


def test_kerberos_error_code_native_labels():
    actual = kerb.KerberosErrorCode.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosErrorCode.none] == "KDC_ERR_NONE"


def test_kerberos_message_type_native_labels():
    actual = kerb.KerberosMessageType.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosMessageType.as_req] == "AS-REQ"


def test_kerberos_pa_data_type_native_labels():
    actual = kerb.KerberosPADataType.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosPADataType.tgs_req] == "PA-TGS-REQ"


def test_kerberos_principal_name_type_native_labels():
    actual = kerb.KerberosPrincipalNameType.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosPrincipalNameType.principal] == "NT-PRINCIPAL"


def test_kerberos_host_address_type_native_labels():
    actual = kerb.KerberosHostAddressType.native_labels()

    assert isinstance(actual, dict)
    assert actual[kerb.KerberosHostAddressType.ipv4] == "IPv4"


def test_unpack_unknown_krb():
    sequence = pack_asn1_sequence(
        [
            pack_asn1(TagClass.context_specific, True, 0, pack_asn1_integer(5)),
            pack_asn1(TagClass.context_specific, True, 1, pack_asn1_integer(0)),
        ]
    )
    actual = sp.unpack_token(sequence, unwrap=True)

    assert isinstance(actual, kerb.KerberosV5Msg)
    assert actual.PVNO == 5
    assert isinstance(actual.sequence, dict)

    assert actual.sequence[0].tag_class == TagClass.universal
    assert not actual.sequence[0].constructed
    assert actual.sequence[0].tag_number == TypeTagNumber.integer
    assert actual.sequence[0].b_data == b"\x05"

    assert actual.sequence[1].tag_class == TagClass.universal
    assert not actual.sequence[1].constructed
    assert actual.sequence[1].tag_number == TypeTagNumber.integer
    assert actual.sequence[1].b_data == b"\x00"


def test_unpack_krb_as_req():
    data = get_data("krb_as_req")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, kerb.KrbAsReq)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.as_req
    assert isinstance(actual.padata, list)
    assert len(actual.padata) == 2

    assert actual.padata[0].data_type == kerb.KerberosPADataType.enc_timestamp
    assert (
        actual.padata[0].b_value == b"\x30\x41\xA0\x03\x02\x01\x12\xA2\x3A\x04\x38\x07\x40\x46\x03\xA8"
        b"\x69\xC9\x31\x76\xE2\x8E\xDA\xD1\x34\xCE\x7F\xC4\xC8\x73\x58\x0D"
        b"\xF4\x61\x1C\x85\x5F\x43\xF6\xAA\x9E\x48\xE2\xF0\x8C\xC2\x88\x70"
        b"\xAA\xBC\xF0\xF7\xF2\xD4\xA2\xC2\xE3\x53\xDE\x81\xF7\x30\x2F\xAF"
        b"\x7C\x85\x12"
    )
    pa1_val = actual.padata[0].value
    assert isinstance(pa1_val, kerb.EncryptedData)
    assert pa1_val.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert pa1_val.kvno is None
    assert (
        pa1_val.cipher == b"\x07\x40\x46\x03\xA8\x69\xC9\x31\x76\xE2\x8E\xDA\xD1\x34\xCE\x7F"
        b"\xC4\xC8\x73\x58\x0D\xF4\x61\x1C\x85\x5F\x43\xF6\xAA\x9E\x48\xE2"
        b"\xF0\x8C\xC2\x88\x70\xAA\xBC\xF0\xF7\xF2\xD4\xA2\xC2\xE3\x53\xDE"
        b"\x81\xF7\x30\x2F\xAF\x7C\x85\x12"
    )

    assert actual.padata[1].data_type == 149
    assert actual.padata[1].b_value == b""
    assert actual.padata[1].value == b""

    assert isinstance(actual.req_body, kerb.KdcReqBody)
    assert actual.req_body.additional_tickets is None
    assert actual.req_body.addresses is None
    assert actual.req_body.cname == kerb.PrincipalName(kerb.KerberosPrincipalNameType.principal, [b"vagrant-domain"])
    assert actual.req_body.enc_authorization_data is None
    assert actual.req_body.etype == [
        kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96,
        kerb.KerberosEncryptionType.aes128_cts_hmac_sha1_96,
        kerb.KerberosEncryptionType.des3_cbc_sha1,
        kerb.KerberosEncryptionType.rc4_hmac,
    ]
    assert actual.req_body.kdc_options == 1073741824
    assert actual.req_body.nonce == 734266074
    assert actual.req_body.postdated_from is None
    assert actual.req_body.postdated_till == datetime.datetime(2020, 6, 14, 7, 4, 20, tzinfo=datetime.timezone.utc)
    assert actual.req_body.realm == b"DOMAIN.LOCAL"
    assert actual.req_body.rtime is None
    assert actual.req_body.sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.srv_inst, [b"krbtgt", b"DOMAIN.LOCAL"]
    )

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert isinstance(actual, dict)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "AS-REQ (10)"
    assert isinstance(actual["padata"], list)
    assert len(actual["padata"]) == 2
    assert actual["padata"][0]["padata-type"] == "PA-ENC-TIMESTAMP (2)"
    assert actual["padata"][0]["padata-value"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["padata"][0]["padata-value"]["kvno"] is None
    assert (
        actual["padata"][0]["padata-value"]["cipher"] == "07404603A869C93176E28EDAD134CE7F"
        "C4C873580DF4611C855F43F6AA9E48E2"
        "F08CC28870AABCF0F7F2D4A2C2E353DE"
        "81F7302FAF7C8512"
    )
    assert actual["padata"][1]["padata-type"] == "PA-REQ-ENC-PA-REP (149)"
    assert actual["padata"][1]["padata-value"] == ""
    assert actual["req-body"]["kdc-options"]["raw"] == 1073741824
    assert actual["req-body"]["kdc-options"]["flags"] == ["forwardable (1073741824)"]
    assert actual["req-body"]["cname"]["name-type"] == "NT-PRINCIPAL (1)"
    assert actual["req-body"]["cname"]["name-string"] == ["vagrant-domain"]
    assert actual["req-body"]["realm"] == "DOMAIN.LOCAL"
    assert actual["req-body"]["sname"]["name-type"] == "NT-SRV-INST (2)"
    assert actual["req-body"]["sname"]["name-string"] == ["krbtgt", "DOMAIN.LOCAL"]
    assert actual["req-body"]["from"] is None
    assert actual["req-body"]["till"] == "2020-06-14T07:04:20+00:00"
    assert actual["req-body"]["rtime"] is None
    assert actual["req-body"]["nonce"] == 734266074
    assert actual["req-body"]["etype"] == [
        "AES256_CTS_HMAC_SHA1_96 (18)",
        "AES128_CTS_HMAC_SHA1_96 (17)",
        "DES3_CBC_SHA1 (16)",
        "RC4_HMAC (23)",
    ]
    assert actual["req-body"]["addresses"] is None
    assert actual["req-body"]["enc-authorization-data"] is None
    assert actual["req-body"]["additional-tickets"] is None


def test_unpack_krb_tgs_req():
    data = get_data("krb_tgs_req")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, kerb.KrbTgsReq)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.tgs_req
    assert isinstance(actual.padata, list)
    assert len(actual.padata) == 1
    assert actual.padata[0].data_type == kerb.KerberosPADataType.tgs_req
    assert isinstance(actual.padata[0].b_value, bytes)

    pa1_val = actual.padata[0].value
    assert pa1_val.PVNO == 5
    assert pa1_val.MESSAGE_TYPE == kerb.KerberosMessageType.ap_req
    assert pa1_val.ap_options == 0
    assert isinstance(pa1_val.authenticator.cipher, bytes)
    assert pa1_val.authenticator.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert pa1_val.authenticator.kvno is None
    assert isinstance(pa1_val.ticket.enc_part.cipher, bytes)
    assert pa1_val.ticket.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert pa1_val.ticket.enc_part.kvno == 2
    assert pa1_val.ticket.realm == b"DOMAIN.LOCAL"
    assert pa1_val.ticket.sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.srv_inst, [b"krbtgt", b"DOMAIN.LOCAL"]
    )
    assert pa1_val.ticket.tkt_vno == 5

    assert actual.req_body.additional_tickets is None
    assert actual.req_body.addresses is None
    assert actual.req_body.cname is None
    assert actual.req_body.enc_authorization_data is None
    assert actual.req_body.etype == [
        kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96,
        kerb.KerberosEncryptionType.aes128_cts_hmac_sha1_96,
        kerb.KerberosEncryptionType.des3_cbc_sha1,
        kerb.KerberosEncryptionType.rc4_hmac,
    ]
    assert actual.req_body.kdc_options == 1073807360
    assert actual.req_body.nonce == 333512069
    assert actual.req_body.postdated_from is None
    assert actual.req_body.postdated_till == datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    assert actual.req_body.realm == b"DOMAIN.LOCAL"
    assert actual.req_body.rtime is None
    assert actual.req_body.sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.srv_hst, [b"HTTP", b"server2019.domain.local"]
    )

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "TGS-REQ (12)"
    assert isinstance(actual["padata"], list)
    assert len(actual["padata"]) == 1
    assert actual["padata"][0]["padata-type"] == "PA-TGS-REQ (1)"
    assert actual["padata"][0]["padata-value"]["pvno"] == 5
    assert actual["padata"][0]["padata-value"]["msg-type"] == "AP-REQ (14)"
    assert actual["padata"][0]["padata-value"]["ap-options"]["raw"] == 0
    assert actual["padata"][0]["padata-value"]["ap-options"]["flags"] == []
    assert actual["padata"][0]["padata-value"]["ticket"]["tkt-vno"] == 5
    assert actual["padata"][0]["padata-value"]["ticket"]["realm"] == "DOMAIN.LOCAL"
    assert actual["padata"][0]["padata-value"]["ticket"]["sname"]["name-type"] == "NT-SRV-INST (2)"
    assert actual["padata"][0]["padata-value"]["ticket"]["sname"]["name-string"] == ["krbtgt", "DOMAIN.LOCAL"]
    assert actual["padata"][0]["padata-value"]["ticket"]["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["padata"][0]["padata-value"]["ticket"]["enc-part"]["kvno"] == 2
    assert isinstance(actual["padata"][0]["padata-value"]["ticket"]["enc-part"]["cipher"], str)
    assert actual["padata"][0]["padata-value"]["authenticator"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["padata"][0]["padata-value"]["authenticator"]["kvno"] is None
    assert isinstance(actual["padata"][0]["padata-value"]["authenticator"]["cipher"], str)
    assert actual["req-body"]["kdc-options"]["raw"] == 1073807360
    assert actual["req-body"]["kdc-options"]["flags"] == ["forwardable (1073741824)", "canonicalize (65536)"]
    assert actual["req-body"]["cname"] is None
    assert actual["req-body"]["realm"] == "DOMAIN.LOCAL"
    assert actual["req-body"]["sname"]["name-type"] == "NT-SRV-HST (3)"
    assert actual["req-body"]["sname"]["name-string"] == ["HTTP", "server2019.domain.local"]
    assert actual["req-body"]["from"] is None
    assert actual["req-body"]["till"] == "1970-01-01T00:00:00+00:00"
    assert actual["req-body"]["rtime"] is None
    assert actual["req-body"]["etype"] == [
        "AES256_CTS_HMAC_SHA1_96 (18)",
        "AES128_CTS_HMAC_SHA1_96 (17)",
        "DES3_CBC_SHA1 (16)",
        "RC4_HMAC (23)",
    ]
    assert actual["req-body"]["addresses"] is None
    assert actual["req-body"]["enc-authorization-data"] is None
    assert actual["req-body"]["additional-tickets"] is None


def test_unpack_krb_as_rep():
    data = get_data("krb_as_rep")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, kerb.KrbAsRep)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.as_rep
    assert actual.cname == kerb.PrincipalName(kerb.KerberosPrincipalNameType.principal, [b"vagrant-domain"])
    assert actual.crealm == b"DOMAIN.LOCAL"

    assert isinstance(actual.enc_part.cipher, bytes)
    assert actual.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.enc_part.kvno == 11

    assert isinstance(actual.padata, list)
    assert len(actual.padata) == 1
    assert actual.padata[0].data_type == kerb.KerberosPADataType.etype_info2
    assert (
        actual.padata[0].b_value == b"\x30\x25\x30\x23\xA0\x03\x02\x01\x12\xA1\x1C\x1B\x1A\x44\x4F\x4D"
        b"\x41\x49\x4E\x2E\x4C\x4F\x43\x41\x4C\x76\x61\x67\x72\x61\x6E\x74"
        b"\x2D\x64\x6F\x6D\x61\x69\x6E"
    )
    pa1_val = actual.padata[0].value
    assert isinstance(pa1_val, list)
    assert len(pa1_val) == 1
    assert pa1_val[0].etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert pa1_val[0].salt == b"DOMAIN.LOCALvagrant-domain"
    assert pa1_val[0].s2kparams is None

    assert isinstance(actual.ticket.enc_part.cipher, bytes)
    assert actual.ticket.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.ticket.enc_part.kvno == 2
    assert actual.ticket.realm == b"DOMAIN.LOCAL"
    assert actual.ticket.sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.srv_inst, [b"krbtgt", b"DOMAIN.LOCAL"]
    )
    assert actual.ticket.tkt_vno == 5

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "AS-REP (11)"
    assert isinstance(actual["padata"], list)
    assert len(actual["padata"]) == 1
    assert actual["padata"][0]["padata-type"] == "PA-ETYPE-INFO2 (19)"
    assert isinstance(actual["padata"][0]["padata-value"], list)
    assert len(actual["padata"][0]["padata-value"]) == 1
    assert actual["padata"][0]["padata-value"][0]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["padata"][0]["padata-value"][0]["salt"] == "444F4D41494E2E4C4F43414C76616772616E742D646F6D61696E"
    assert actual["padata"][0]["padata-value"][0]["s2kparams"] is None
    assert actual["crealm"] == "DOMAIN.LOCAL"
    assert actual["cname"]["name-type"] == "NT-PRINCIPAL (1)"
    assert actual["cname"]["name-string"] == ["vagrant-domain"]
    assert actual["ticket"]["tkt-vno"] == 5
    assert actual["ticket"]["realm"] == "DOMAIN.LOCAL"
    assert actual["ticket"]["sname"]["name-type"] == "NT-SRV-INST (2)"
    assert actual["ticket"]["sname"]["name-string"] == ["krbtgt", "DOMAIN.LOCAL"]
    assert actual["ticket"]["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["ticket"]["enc-part"]["kvno"] == 2
    assert isinstance(actual["ticket"]["enc-part"]["cipher"], str)
    assert actual["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["enc-part"]["kvno"] == 11
    assert isinstance(actual["enc-part"]["cipher"], str)


def test_unpack_krb_tgs_rep():
    data = get_data("krb_tgs_rep")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, kerb.KrbTgsRep)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.tgs_rep
    assert actual.cname == kerb.PrincipalName(kerb.KerberosPrincipalNameType.principal, [b"vagrant-domain"])
    assert actual.crealm == b"DOMAIN.LOCAL"

    assert isinstance(actual.enc_part.cipher, bytes)
    assert actual.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.enc_part.kvno is None

    assert actual.padata is None

    assert isinstance(actual.ticket.enc_part.cipher, bytes)
    assert actual.ticket.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.ticket.enc_part.kvno == 6
    assert actual.ticket.realm == b"DOMAIN.LOCAL"
    assert actual.ticket.sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.srv_hst, [b"HTTP", b"server2019.domain.local"]
    )
    assert actual.ticket.tkt_vno == 5

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "TGS-REP (13)"
    assert actual["padata"] is None
    assert actual["crealm"] == "DOMAIN.LOCAL"
    assert actual["cname"]["name-type"] == "NT-PRINCIPAL (1)"
    assert actual["cname"]["name-string"] == ["vagrant-domain"]
    assert actual["ticket"]["tkt-vno"] == 5
    assert actual["ticket"]["realm"] == "DOMAIN.LOCAL"
    assert actual["ticket"]["sname"]["name-type"] == "NT-SRV-HST (3)"
    assert actual["ticket"]["sname"]["name-string"] == ["HTTP", "server2019.domain.local"]
    assert actual["ticket"]["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["ticket"]["enc-part"]["kvno"] == 6
    assert isinstance(actual["ticket"]["enc-part"]["cipher"], str)
    assert actual["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["enc-part"]["kvno"] is None
    assert isinstance(actual["enc-part"]["cipher"], str)


def test_unpack_krb_ap_req():
    data = get_data("initial_context_token_krb_ap_req")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.kerberos.value

    actual = actual.token

    assert isinstance(actual, kerb.KrbApReq)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.ap_req
    assert actual.ap_options == kerb.KerberosAPOptions.mutual_required
    assert isinstance(actual.authenticator.cipher, bytes)
    assert actual.authenticator.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.authenticator.kvno is None
    assert isinstance(actual.ticket.enc_part.cipher, bytes)
    assert actual.ticket.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.ticket.enc_part.kvno == 6
    assert actual.ticket.realm == b"DOMAIN.LOCAL"
    assert actual.ticket.sname == kerb.PrincipalName(kerb.KerberosPrincipalNameType.srv_hst, [b"host", b"dc01"])
    assert actual.ticket.tkt_vno == 5

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "AP-REQ (14)"
    assert actual["ap-options"]["raw"] == 32
    assert actual["ap-options"]["flags"] == ["mutual-required (32)"]
    assert actual["ticket"]["tkt-vno"] == 5
    assert actual["ticket"]["realm"] == "DOMAIN.LOCAL"
    assert actual["ticket"]["sname"]["name-type"] == "NT-SRV-HST (3)"
    assert actual["ticket"]["sname"]["name-string"] == ["host", "dc01"]
    assert actual["ticket"]["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["ticket"]["enc-part"]["kvno"] == 6
    assert isinstance(actual["ticket"]["enc-part"]["cipher"], str)
    assert actual["authenticator"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["authenticator"]["kvno"] is None
    assert isinstance(actual["authenticator"]["cipher"], str)


def test_unpack_krb_ap_req_unknown_options():
    data = get_data("initial_context_token_krb_ap_req")
    data = data[:40] + b"\x10" + data[41:]  # This is where ap-options is set

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.kerberos.value

    actual = actual.token

    assert isinstance(actual, kerb.KrbApReq)
    assert actual.ap_options == 16


def test_unpack_krb_ap_rep():
    data = get_data("initial_context_token_krb_ap_rep")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.kerberos.value

    actual = actual.token

    assert isinstance(actual, kerb.KrbApRep)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.ap_rep
    assert isinstance(actual.enc_part.cipher, bytes)
    assert actual.enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert actual.enc_part.kvno is None

    # Test pyspnego-parse dict.
    actual = kerb.parse_kerberos_token(actual)
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "AP-REP (15)"
    assert actual["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["enc-part"]["kvno"] is None
    assert isinstance(actual["enc-part"]["cipher"], str)


def test_unpack_krb_error():
    data = get_data("krb_error")

    actual = sp.unpack_token(data)
    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)

    assert isinstance(actual, kerb.KrbError)
    assert actual.PVNO == 5
    assert actual.MESSAGE_TYPE == kerb.KerberosMessageType.error
    assert actual.cname is None
    assert actual.crealm is None
    assert actual.ctime is None
    assert actual.cusec is None
    assert isinstance(actual.e_data, bytes)
    assert actual.e_text is None
    assert actual.error_code == kerb.KerberosErrorCode.preauth_required
    assert actual.realm == b"DOMAIN.LOCAL"
    assert actual.sname == kerb.PrincipalName(kerb.KerberosPrincipalNameType.srv_inst, [b"krbtgt", b"DOMAIN.LOCAL"])
    assert actual.stime == datetime.datetime(2020, 6, 13, 21, 4, 23, tzinfo=datetime.timezone.utc)
    assert actual.susec == 748591

    actual = kerb.parse_kerberos_token(actual, encoding="utf-8")
    assert actual["pvno"] == 5
    assert actual["msg-type"] == "KRB-ERROR (30)"
    assert actual["ctime"] is None
    assert actual["cusec"] is None
    assert actual["stime"] == "2020-06-13T21:04:23+00:00"
    assert actual["susec"] == 748591
    assert actual["error-code"] == "KDC_ERR_PREAUTH_REQUIRED (25)"
    assert actual["crealm"] is None
    assert actual["cname"] is None
    assert actual["realm"] == "DOMAIN.LOCAL"
    assert actual["sname"]["name-type"] == "NT-SRV-INST (2)"
    assert actual["sname"]["name-string"] == ["krbtgt", "DOMAIN.LOCAL"]
    assert actual["e-text"] is None
    assert isinstance(actual["e-data"], str)


def test_padata_unknown_type():
    value = b"".join(
        [
            pack_asn1(TagClass.context_specific, True, 1, pack_asn1_integer(1024)),
            pack_asn1(TagClass.context_specific, True, 2, pack_asn1_octet_string(b"")),
        ]
    )
    padata = kerb.PAData.unpack(value)

    assert padata.data_type == 1024
    assert padata.b_value == b""
    assert padata.value == b""

    actual = kerb.parse_kerberos_token(padata)

    assert isinstance(actual, dict)
    assert actual["padata-type"] == "UNKNOWN (1024)"
    assert actual["padata-value"] == ""


def test_req_body_addresses():
    value = b"".join(
        [
            pack_asn1(TagClass.context_specific, True, 0, pack_asn1_bit_string(b"\x00\x00\x00\x00")),
            pack_asn1(TagClass.context_specific, True, 2, pack_asn1_general_string(b"DOMAIN.LOCAL")),
            pack_asn1(TagClass.context_specific, True, 7, pack_asn1_integer(1)),
            pack_asn1(
                TagClass.context_specific,
                True,
                8,
                pack_asn1_sequence([pack_asn1_integer(kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96)]),
            ),
            pack_asn1(
                TagClass.context_specific,
                True,
                9,
                pack_asn1_sequence(
                    [
                        pack_asn1_sequence(
                            [
                                pack_asn1(
                                    TagClass.context_specific,
                                    True,
                                    0,
                                    pack_asn1_integer(kerb.KerberosHostAddressType.ipv4),
                                ),
                                pack_asn1(
                                    TagClass.context_specific, True, 1, pack_asn1_octet_string(b"dc01.domain.local")
                                ),
                            ]
                        )
                    ]
                ),
            ),
        ]
    )
    req_body = kerb.KdcReqBody.unpack(value)

    assert isinstance(req_body.addresses, list)
    assert len(req_body.addresses) == 1
    assert req_body.addresses[0].addr_type == kerb.KerberosHostAddressType.ipv4
    assert req_body.addresses[0].value == b"dc01.domain.local"

    actual = kerb.parse_kerberos_token(req_body)
    assert isinstance(actual, dict)
    assert actual["addresses"][0]["addr-type"] == "IPv4 (2)"
    assert actual["addresses"][0]["address"] == "dc01.domain.local"


def test_req_body_ticket():
    ticket = pack_asn1(
        TagClass.application,
        True,
        1,
        pack_asn1_sequence(
            [
                pack_asn1(TagClass.context_specific, True, 0, pack_asn1_integer(5)),
                pack_asn1(TagClass.context_specific, True, 1, pack_asn1_general_string(b"DOMAIN.LOCAL")),
                pack_asn1(
                    TagClass.context_specific,
                    True,
                    2,
                    pack_asn1_sequence(
                        [
                            pack_asn1(
                                TagClass.context_specific,
                                True,
                                0,
                                pack_asn1_integer(kerb.KerberosPrincipalNameType.principal),
                            ),
                            pack_asn1(
                                TagClass.context_specific,
                                True,
                                1,
                                pack_asn1_sequence(
                                    [
                                        pack_asn1_general_string(b"vagrant-domain"),
                                    ]
                                ),
                            ),
                        ]
                    ),
                ),
                pack_asn1(
                    TagClass.context_specific,
                    True,
                    3,
                    pack_asn1_sequence(
                        [
                            pack_asn1(
                                TagClass.context_specific,
                                True,
                                0,
                                pack_asn1_integer(kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96),
                            ),
                            pack_asn1(TagClass.context_specific, True, 2, pack_asn1_octet_string(b"\x00\x01")),
                        ]
                    ),
                ),
            ]
        ),
    )
    value = b"".join(
        [
            pack_asn1(TagClass.context_specific, True, 0, pack_asn1_bit_string(b"\x00\x00\x00\x00")),
            pack_asn1(TagClass.context_specific, True, 2, pack_asn1_general_string(b"DOMAIN.LOCAL")),
            pack_asn1(TagClass.context_specific, True, 7, pack_asn1_integer(1)),
            pack_asn1(
                TagClass.context_specific,
                True,
                8,
                pack_asn1_sequence([pack_asn1_integer(kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96)]),
            ),
            pack_asn1(TagClass.context_specific, True, 11, pack_asn1_sequence([ticket])),
        ]
    )
    req_body = kerb.KdcReqBody.unpack(value)

    assert isinstance(req_body.additional_tickets, list)
    assert len(req_body.additional_tickets) == 1
    assert req_body.additional_tickets[0].enc_part.cipher == b"\x00\x01"
    assert req_body.additional_tickets[0].enc_part.etype == kerb.KerberosEncryptionType.aes256_cts_hmac_sha1_96
    assert req_body.additional_tickets[0].enc_part.kvno is None
    assert req_body.additional_tickets[0].realm == b"DOMAIN.LOCAL"
    assert req_body.additional_tickets[0].sname == kerb.PrincipalName(
        kerb.KerberosPrincipalNameType.principal, [b"vagrant-domain"]
    )
    assert req_body.additional_tickets[0].tkt_vno == 5

    actual = kerb.parse_kerberos_token(req_body)
    assert isinstance(actual, dict)
    assert actual["additional-tickets"][0]["tkt-vno"] == 5
    assert actual["additional-tickets"][0]["realm"] == "DOMAIN.LOCAL"
    assert actual["additional-tickets"][0]["sname"]["name-type"] == "NT-PRINCIPAL (1)"
    assert actual["additional-tickets"][0]["sname"]["name-string"] == ["vagrant-domain"]
    assert actual["additional-tickets"][0]["enc-part"]["etype"] == "AES256_CTS_HMAC_SHA1_96 (18)"
    assert actual["additional-tickets"][0]["enc-part"]["kvno"] is None
    assert actual["additional-tickets"][0]["enc-part"]["cipher"] == "0001"
