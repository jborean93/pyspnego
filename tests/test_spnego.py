# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

import spnego._spnego as sp
from spnego._asn1 import TagClass, pack_asn1, pack_asn1_object_identifier
from spnego._context import GSSMech
from spnego._kerberos import KrbApRep, KrbApReq
from spnego._ntlm_raw.messages import Challenge, MessageType

from .conftest import get_data


@pytest.mark.parametrize(
    "value, expected",
    [
        (GSSMech.kerberos.value, b"\x30\x0B\x06\x09\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"),
        (
            [GSSMech.kerberos.value, GSSMech.ntlm.value],
            b"\x30\x17\x06\x09\x2A\x86\x48\x86"
            b"\xF7\x12\x01\x02\x02\x06\x0A\x2B"
            b"\x06\x01\x04\x01\x82\x37\x02\x02"
            b"\x0A",
        ),
    ],
)
def test_pack_mech_type_list(value, expected):
    actual = sp.pack_mech_type_list(value)
    import base64

    print(base64.b16encode(actual).decode())
    assert actual == expected


def test_spnego_context_flags_native_labels():
    actual = sp.ContextFlags.native_labels()

    assert isinstance(actual, dict)
    assert actual[sp.ContextFlags.deleg] == "delegFlag"


def test_spnego_neg_state_native_labels():
    actual = sp.NegState.native_labels()

    assert isinstance(actual, dict)
    assert actual[sp.NegState.accept_incomplete] == "accept-incomplete"


def test_initial_context_token_unknown_token():
    token = sp.InitialContextToken(GSSMech.ntlm, b"\x00\x00\x00\x00")

    assert isinstance(token, sp.InitialContextToken)
    assert token.this_mech == GSSMech.ntlm.value
    assert token.inner_context_token == b"\x00\x00\x00\x00"
    assert token.token == b"\x00\x00\x00\x00"


def test_initial_context_token_unknown_mech():
    token = sp.InitialContextToken("1.2.3.4.5", b"\x00\x00\x00\x00")

    assert isinstance(token, sp.InitialContextToken)
    assert token.this_mech == "1.2.3.4.5"
    assert token.inner_context_token == b"\x00\x00\x00\x00"
    assert token.token == b"\x00\x00\x00\x00"


def test_unpack_initial_context_token_unknown_mech():
    data = pack_asn1(TagClass.application, True, 0, pack_asn1_object_identifier("1.2.3.4.5") + b"\x00\x00\x00\x00")
    token = sp.unpack_token(data)

    assert token == data


def test_unpack_initial_context_token_invalid_application_tag():
    data = pack_asn1(TagClass.application, True, 1, b"\x00\x00\x00\x00")

    expected = "Expecting a tag number of 0 not 1 for InitialContextToken"
    with pytest.raises(ValueError, match=expected):
        sp.unpack_token(data)


def test_unpack_initial_context_token_invalid_context_specific_tag():
    data = pack_asn1(TagClass.context_specific, True, 2, b"\x00\x00\x00\x00")

    expected = "Unknown NegotiationToken CHOICE 2, only expecting 0 or 1"
    with pytest.raises(ValueError, match=expected):
        sp.unpack_token(data)


def test_unpack_neg_token_init():
    data = get_data("initial_context_token_neg_token_init")
    actual = sp.unpack_token(data)

    assert isinstance(actual, sp.NegTokenInit)
    assert actual.hint_address is None
    assert actual.hint_name is None
    assert actual.mech_list_mic is None
    assert isinstance(actual.mech_token, bytes)
    assert actual.mech_types == ["1.2.840.113554.1.2.2", "1.3.6.1.4.1.311.2.2.10"]
    assert actual.req_flags is None

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.spnego.value
    assert isinstance(actual.token, sp.NegTokenInit)


def test_unpack_neg_token_init2():
    data = get_data("initial_context_token_neg_token_init2")
    actual = sp.unpack_token(data)

    assert isinstance(actual, sp.NegTokenInit)
    assert actual.hint_address is None
    assert actual.hint_name == b"not_defined_in_RFC4178@please_ignore"
    assert actual.mech_list_mic is None
    assert actual.mech_token is None
    assert actual.mech_types == [
        "1.3.6.1.4.1.311.2.2.30",
        "1.2.840.48018.1.2.2",
        "1.2.840.113554.1.2.2",
        "1.2.840.113554.1.2.2.3",
        "1.3.6.1.4.1.311.2.2.10",
    ]
    assert actual.req_flags is None

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.spnego.value
    assert isinstance(actual.token, sp.NegTokenInit)


def test_unpack_neg_token_resp():
    data = get_data("neg_token_resp")
    actual = sp.unpack_token(data)

    assert isinstance(actual, sp.NegTokenResp)
    assert actual.mech_list_mic is None
    assert actual.neg_state == sp.NegState.accept_complete
    assert isinstance(actual.response_token, bytes)
    assert actual.supported_mech == GSSMech.kerberos.value

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, sp.NegTokenResp)


def test_unpack_krb_ap_req():
    data = get_data("initial_context_token_krb_ap_req")
    actual = sp.unpack_token(data)

    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.kerberos.value
    assert isinstance(actual.token, KrbApReq)


def test_unpack_krb_ap_rep():
    data = get_data("initial_context_token_krb_ap_rep")
    actual = sp.unpack_token(data)

    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, sp.InitialContextToken)
    assert actual.this_mech == GSSMech.kerberos.value
    assert isinstance(actual.token, KrbApRep)


def test_unpack_ntlm():
    data = get_data("ntlm_challenge")
    actual = sp.unpack_token(data)

    assert actual == data

    actual = sp.unpack_token(data, unwrap=True)
    assert isinstance(actual, Challenge)
    assert actual.MESSAGE_TYPE == MessageType.challenge


def test_pack_neg_token_init():
    token = sp.NegTokenInit(
        [GSSMech.kerberos.value, GSSMech.ntlm.value],
        sp.ContextFlags.anon,
        b"\x00\x00\x00\x00",
        mech_list_mic=b"\x01\x01\x01\x01",
    )

    actual = token.pack()
    assert (
        actual == b"\x60\x3D\x06\x06\x2B\x06\x01\x05\x05\x02\xA0\x33\x30\x31\xA0\x19"
        b"\x30\x17\x06\x09\x2A\x86\x48\x86\xF7\x12\x01\x02\x02\x06\x0A\x2B"
        b"\x06\x01\x04\x01\x82\x37\x02\x02\x0A\xA1\x04\x03\x02\x00\x04\xA2"
        b"\x06\x04\x04\x00\x00\x00\x00\xA3\x06\x04\x04\x01\x01\x01\x01"
    )

    token = sp.unpack_token(actual)
    assert token.mech_types == ["1.2.840.113554.1.2.2", "1.3.6.1.4.1.311.2.2.10"]
    assert token.req_flags == sp.ContextFlags.deleg
    assert token.mech_token == b"\x00\x00\x00\x00"
    assert token.hint_name is None
    assert token.hint_address is None
    assert token.mech_list_mic == b"\x01\x01\x01\x01"


def test_pack_neg_token_init2():
    token = sp.NegTokenInit(
        [GSSMech.kerberos.value, GSSMech.ntlm.value],
        sp.ContextFlags.anon,
        mech_token=b"\x00\x00\x00\x00",
        hint_name=b"spn",
        hint_address=b"not_defined_in_RFC4178@please_ignore",
        mech_list_mic=b"\x01\x01\x01\x01",
    )

    actual = token.pack()

    assert (
        actual == b"\x60\x70\x06\x06\x2B\x06\x01\x05\x05\x02\xA0\x66\x30\x64\xA0\x19"
        b"\x30\x17\x06\x09\x2A\x86\x48\x86\xF7\x12\x01\x02\x02\x06\x0A\x2B"
        b"\x06\x01\x04\x01\x82\x37\x02\x02\x0A\xA1\x04\x03\x02\x00\x04\xA2"
        b"\x06\x04\x04\x00\x00\x00\x00\xA3\x31\x30\x2F\xA0\x05\x1B\x03\x73"
        b"\x70\x6E\xA1\x26\x04\x24\x6E\x6F\x74\x5F\x64\x65\x66\x69\x6E\x65"
        b"\x64\x5F\x69\x6E\x5F\x52\x46\x43\x34\x31\x37\x38\x40\x70\x6C\x65"
        b"\x61\x73\x65\x5F\x69\x67\x6E\x6F\x72\x65\xA4\x06\x04\x04\x01\x01"
        b"\x01\x01"
    )

    token = sp.unpack_token(actual)
    assert token.mech_types == ["1.2.840.113554.1.2.2", "1.3.6.1.4.1.311.2.2.10"]
    assert token.req_flags == sp.ContextFlags.deleg
    assert token.mech_token == b"\x00\x00\x00\x00"
    assert token.hint_name == b"spn"
    assert token.hint_address == b"not_defined_in_RFC4178@please_ignore"
    assert token.mech_list_mic == b"\x01\x01\x01\x01"


def test_pack_neg_token_resp():
    token = sp.NegTokenResp(sp.NegState.request_mic, GSSMech.ntlm.value, b"\x00\x00\x00\x00", b"\x01\x01\x01\x01")

    actual = token.pack()
    assert (
        actual == b"\xA1\x25\x30\x23\xA0\x03\x0A\x01\x03\xA1\x0C\x06\x0A\x2B\x06\x01"
        b"\x04\x01\x82\x37\x02\x02\x0A\xA2\x06\x04\x04\x00\x00\x00\x00\xA3"
        b"\x06\x04\x04\x01\x01\x01\x01"
    )

    token = sp.unpack_token(actual)
    assert token.neg_state == sp.NegState.request_mic
    assert token.supported_mech == GSSMech.ntlm.value
    assert token.response_token == b"\x00\x00\x00\x00"
    assert token.mech_list_mic == b"\x01\x01\x01\x01"
