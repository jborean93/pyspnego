# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import struct
from collections import namedtuple

from spnego._asn1 import (
    pack_asn1,
    pack_asn1_enumerated,
    pack_asn1_object_identifier,
    pack_asn1_octet_string,
    pack_asn1_sequence,
    TagClass,
    TypeTagNumber,
    unpack_asn1,
    unpack_asn1_bit_string,
    unpack_asn1_enumerated,
    unpack_asn1_object_identifier,
)


NegTokenInit = namedtuple('NegTokenInit', ['mech_types', 'req_flags', 'mech_token', 'mech_list_mic'])
NegTokenResp = namedtuple('NegTokenResp', ['neg_state', 'supported_mech', 'response_token', 'mech_list_mic'])

SPNEGO_OID = '1.3.6.1.5.5.2'


class NegState:
    accept_complete = 0
    accept_incomplete = 1
    reject = 2
    request_mic = 3


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
    elements.append(pack_asn1(TagClass.context_specific, True, 0, b_mech_list))

    # mechToken
    if mech_token:
        elements.append(pack_asn1(TagClass.context_specific, True, 2, pack_asn1_octet_string(mech_token)))

    # mechListMIC
    if mech_list_mic:
        elements.append(pack_asn1(TagClass.context_specific, True, 3, pack_asn1_octet_string(mech_list_mic)))

    neg_token_init = pack_asn1_sequence(elements)
    return _pack_negotiation_token(neg_token_init, 0)


def _unpack_neg_token_init(b_data):
    # TODO: NegTokenInit2 could be sent by the server which has a slightly different setup.
    tag_class, _, tag_number, token_data, _ = unpack_asn1(b_data)
    if tag_class != TagClass.universal and tag_number != TypeTagNumber.sequence:
        raise ValueError("Expected SEQUENCE in NegTokenInit but got tag class %d and tag number %d"
                         % (tag_class, tag_number))

    entries = {}
    while token_data:
        sequence_class, _, sequence_no, sequence_data, token_data = unpack_asn1(token_data)
        if sequence_class != TagClass.context_specific:
            raise ValueError("Expected explicit tagged sequence entries but got tag class of %d" % sequence_class)

        if sequence_no == 0:
            mech_list_class, _, mech_list_tag, mech_list_data, _ = unpack_asn1(sequence_data)
            if mech_list_class != TagClass.universal and mech_list_tag != TypeTagNumber.sequence:
                raise ValueError("Expected SEQUENCE of mechTypes in NegTokenInit but got tag class %d and tag "
                                 "number %d" % (mech_list_class, mech_list_tag))

            unpack_data = []
            while mech_list_data:
                mech_class, _, mech_tag, mech_data, mech_list_data = unpack_asn1(mech_list_data)
                if mech_class != TagClass.universal and mech_tag != TypeTagNumber.object_identifier:
                    raise ValueError("Expected SEQUENCE of MechType in mechTypes for NegTokenInit but got tag class "
                                     "%d and tag number %d" % (mech_class, mech_tag))

                unpack_data.append(unpack_asn1_object_identifier(mech_data))

        elif sequence_no == 1:
            req_class, _, req_tag, req_data, _ = unpack_asn1(sequence_data)
            if req_class != TagClass.universal and req_tag != TypeTagNumber.bit_string:
                raise ValueError("Expected ContextFlags BIT STRING in NegTokenInit but got tag class %d and tag "
                                 "number %d" % (req_class, req_tag))

            # Can be up to 32 bits in length but RFC 4178 states
            # "Implementations should not expect to receive exactly 32 bits in an encoding of ContextFlags."
            # The spec also documents req flags up to 6 so let's just get the last byte. In reality we shouldn't ever
            # receive this but it's left here for posterity.
            unpack_data = struct.unpack("B", unpack_asn1_bit_string(req_data)[-1])[0]

        elif sequence_no == 2:
            token_class, _, token_tag, unpack_data, _ = unpack_asn1(sequence_data)
            if token_class != TagClass.universal and token_tag != TypeTagNumber.octet_string:
                raise ValueError("Expected mechToken OCTET STRING in NegTokenInit but got tag class %d and tag number "
                                 "%d" % (token_class, token_tag))

        elif sequence_no == 3:
            mic_class, _, mic_tag, unpack_data, _ = unpack_asn1(sequence_data)
            if mic_class != TagClass.universal and mic_tag != TypeTagNumber.octet_string:
                raise ValueError("Expected mechListMIC OCTET STRING in NegTokenInit but got tag class %d and tag "
                                 "number %d" % (mic_class, mic_tag))

        else:
            raise ValueError("Unknown sequence number %d found in NegTokenInit token, expecting 0, 1, 2, or 3"
                             % sequence_no)

        entries[sequence_no] = unpack_data

    return NegTokenInit(entries[0], entries.get(1, None), entries.get(2, None), entries.get(3, None))


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
        elements.append(pack_asn1(TagClass.context_specific, True, 0, pack_asn1_enumerated(neg_state)))

    if supported_mech:
        elements.append(pack_asn1(TagClass.context_specific, True, 1, pack_asn1_object_identifier(supported_mech)))

    if response_token:
        elements.append(pack_asn1(TagClass.context_specific, True, 2, pack_asn1_octet_string(response_token)))

    if mech_list_mic:
        elements.append(pack_asn1(TagClass.context_specific, True, 2, pack_asn1_octet_string(mech_list_mic)))

    neg_token_resp = pack_asn1_sequence(elements)
    return _pack_negotiation_token(neg_token_resp, 1)


def _unpack_neg_token_resp(b_data):
    tag_class, _, tag_number, token_data, _ = unpack_asn1(b_data)
    if tag_class != TagClass.universal and tag_number != TypeTagNumber.sequence:
        raise ValueError("Expected SEQUENCE in NegTokenResp but got tag class %d and tag number %d"
                         % (tag_class, tag_number))

    entries = {}
    while token_data:
        sequence_class, _, sequence_no, sequence_data, token_data = unpack_asn1(token_data)
        if sequence_class != TagClass.context_specific:
            raise ValueError("Expected explicit tagged sequence entries but got tag class of %d" % sequence_class)

        if sequence_no == 0:
            state_class, _, state_tag, state, _ = unpack_asn1(sequence_data)
            if state_class != TagClass.universal and state_tag != TypeTagNumber.enumerated:
                raise ValueError("Expected negState ENUMERATED in NegTokenResp but got tag class %d and tag "
                                 "number %d" % (state_class, state_tag))

            unpack_data = unpack_asn1_enumerated(state)

        elif sequence_no == 1:
            mech_class, _, mech_tag, mech, _ = unpack_asn1(sequence_data)
            if mech_class != TagClass.universal and mech_tag != TypeTagNumber.object_identifier:
                raise ValueError("Expected supportedMech MechType in NegTokenResp but got tag class %d and tag "
                                 "number %d" % (mech_class, mech_tag))

            unpack_data = unpack_asn1_object_identifier(mech)

        elif sequence_no == 2:
            token_class, _, token_tag, unpack_data, _ = unpack_asn1(sequence_data)
            if token_class != TagClass.universal and token_tag != TypeTagNumber.octet_string:
                raise ValueError("Expected responseToken OCTET STRING in NegTokenResp but got tag class %d and tag "
                                 "number %d" % (token_class, token_tag))

        elif sequence_no == 3:
            mic_class, _, mic_tag, unpack_data, _ = unpack_asn1(sequence_data)
            if mic_class != TagClass.universal and mic_tag != TypeTagNumber.octet_string:
                raise ValueError("Expected mechListMIC OCTET STRING in NegTokenResp but got tag class %d and tag "
                                 "number %d" % (mic_class, mic_tag))

        else:
            raise ValueError("Unknown sequence number %d found in NegTokenResp token, expecting 0, 1, 2, or 3"
                             % sequence_no)

        entries[sequence_no] = unpack_data

    return NegTokenResp(entries.get(0, None), entries.get(1, None), entries.get(2, None), entries.get(3, None))


def unpack_neg_token(b_data):
    tag_class, constructed, tag_number, b_data, _ = unpack_asn1(b_data)

    if tag_class == TagClass.application:
        # The first token may be encapsulated in the InitialContextToken, we verify the OID is the SPNEGO OID and
        # extract the NegTokenInit inside that.
        if tag_number != 0:
            raise ValueError("Expecting a tag number of 0 not %d for InitialContextToken" % tag_number)

        mech_class, _, tag_number, mech, inner_context_token = unpack_asn1(b_data)
        if mech_class != TagClass.universal and tag_number != TypeTagNumber.object_identifier:
            raise ValueError("Expecting an OID as the first element in the InitialContextToken but got tag class %d "
                             "and tag number %d" % (mech_class, tag_number))

        mech = unpack_asn1_object_identifier(mech)
        if mech != SPNEGO_OID:
            raise ValueError("Expecting a InitialContextToken with a SPNEGO mech but received %s" % mech)

        return unpack_neg_token(inner_context_token)

    elif tag_class == TagClass.context_specific:
        if tag_number == 0:
            return _unpack_neg_token_init(b_data)

        elif tag_number == 1:
            return _unpack_neg_token_resp(b_data)

        else:
            raise ValueError("Expecting a tag number of 0 or 1 not %d for NegotiationToken" % tag_number)

    else:
        raise ValueError("Expecting tag class of 1 or 2 not %d for NegotiationToken" % tag_class)


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
    negotiation_token = pack_asn1(TagClass.context_specific, True, choice, token)
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
    return pack_asn1(TagClass.application, True, 0, b_mech + inner_context_token)
