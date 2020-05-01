# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from collections import namedtuple

from spnego._asn1 import (
    pack_asn1,
    pack_asn1_enumerated,
    pack_asn1_object_identifier,
    pack_asn1_octet_string,
    pack_asn1_sequence,
    TagClass,
)


NegTokenInit = namedtuple('NegTokenInit', ['mech_types', 'req_flags', 'mech_token', 'mech_list_mic'])
NegTokenResp = namedtuple('NegTokenResp', ['neg_state', 'supported_mech', 'response_token', 'mech_list_mic'])

SPNEGO_OID = '1.3.6.1.5.5.2'


def pack_neg_token_init(mech_list, mech_token=None, mech_list_mic=None):
    """
    Creates a SPNEGO NegTokenInit token that is wrapped in an InitialContextToken token.

    MechType ::= OBJECT IDENTIFIER

    MechTypeList ::= SEQUENCE OF MechType

    NegTokenInit ::= SEQUENCE {
        mechTypes       [0] MechTypeList,
        reqFlags        [1] ContextFlags  OPTIONAL,
          -- inherited from RFC 2478 for backward compatibility,
          -- RECOMMENDED to be left out
        mechToken       [2] OCTET STRING  OPTIONAL,
        mechListMIC     [3] OCTET STRING  OPTIONAL,
        ...
    }

    :param mech_list:
    :param mech_token:
    :param mech_list_mic:
    :return:
    """
    elements = []

    # mechTypes
    if not isinstance(mech_list, list):
        mech_list = [mech_list]

    b_mech_list = pack_asn1_sequence([pack_asn1_object_identifier(oid) for oid in mech_list])
    elements.append(pack_asn1(TagClass.context_specific, False, 0, b_mech_list))

    # mechToken
    if mech_token:
        elements.append(pack_asn1(TagClass.context_specific, False, 2, pack_asn1_octet_string(mech_token)))

    # mechListMIC
    if mech_list_mic:
        elements.append(pack_asn1(TagClass.context_specific, False, 3, pack_asn1_octet_string(mech_list_mic)))

    neg_token_init = pack_asn1_sequence(elements)
    return _pack_negotiation_token(neg_token_init, 0)


def pack_neg_token_resp(neg_state=None, supported_mech=None, response_token=None, mech_list_mic=None):
    """
    Creates a SPNEGO NegTokenResp token.

    MechType ::= OBJECT IDENTIFIER

    NegTokenResp ::= SEQUENCE {
        negState       [0] ENUMERATED {
            accept-completed    (0),
            accept-incomplete   (1),
            reject              (2),
            request-mic         (3)
        }                                 OPTIONAL,
          -- REQUIRED in the first reply from the target
        supportedMech   [1] MechType      OPTIONAL,
          -- present only in the first reply from the target
        responseToken   [2] OCTET STRING  OPTIONAL,
        mechListMIC     [3] OCTET STRING  OPTIONAL,
        ...
    }

    :param neg_state:
    :param supported_mech:
    :param response_token:
    :param mech_list_mic:
    :return:
    """
    elements = []

    if neg_state:
        elements.append(pack_asn1(TagClass.context_specific, False, 0, pack_asn1_enumerated(neg_state)))

    if supported_mech:
        elements.append(pack_asn1(TagClass.context_specific, False, 1, pack_asn1_object_identifier(supported_mech)))

    if response_token:
        elements.append(pack_asn1(TagClass.context_specific, False, 2, pack_asn1_octet_string(response_token)))

    if mech_list_mic:
        elements.append(pack_asn1(TagClass.context_specific, False, 2, pack_asn1_octet_string(mech_list_mic)))

    neg_token_resp = pack_asn1_sequence(elements)
    return _pack_negotiation_token(neg_token_resp, 1)


def unpack_neg_token_init(b_data):
    a = ''


def unpack_neg_token_resp(b_data):
    a = ''


def _pack_negotiation_token(token, choice):
    """
    Creates the NegotiationToken for the token choice specified. A NegTokenInit is further wrapped in an
    InitialContextToken as specified in RFC 2743.

    NegotiationToken ::= CHOICE {
        negTokenInit    [0] NegTokenInit,
        negTokenResp    [1] NegTokenResp
    }

    :param token: The token value.
    :param choice: 0 for NegTokenInit and 1 for NegTokenResp.
    :return: Bytes string of the packed token.
    """
    negotiation_token = pack_asn1(TagClass.context_specific, False, choice, token)
    if choice == 0:
        return _pack_initial_context_token(SPNEGO_OID, negotiation_token)
    else:
        return negotiation_token


def _pack_initial_context_token(mech, inner_context_token):
    """
    Creates the InitialContextToken as defined in RFC 2743 3.1 https://www.rfc-editor.org/rfc/rfc2743#section-3.1.

    InitialContextToken ::=
    -- option indication (delegation, etc.) indicated within
    -- mechanism-specific token
    [APPLICATION 0] IMPLICIT SEQUENCE {
            thisMech MechType,
            innerContextToken ANY DEFINED BY thisMech
               -- contents mechanism-specific
               -- ASN.1 structure not required
            }

    :param mech: The mech that the token related to, typically this is SPNEGO.
    :param inner_context_token: The raw data to wrap in the InitialContextToken.
    :return: Byte string of the InitialContextToken.
    """
    b_mech = pack_asn1_object_identifier(mech)
    return pack_asn1(TagClass.application, False, 0, b_mech + inner_context_token)
