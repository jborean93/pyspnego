# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import hashlib
import hmac
import io

from typing import (
    Optional,
    Tuple,
)

from spnego._ntlm_raw.des import (
    DES,
)

from spnego._ntlm_raw.messages import (
    FileTime,
    NegotiateFlags,
    TargetInfo,
)

from spnego._text import (
    text_type,
    to_bytes,
)


def des(k, d):  # type: (bytes, bytes) -> bytes
    """DES encryption.

    Indicates the encryption of an 8-byte data item `d` with the 7-byte key `k` using the Data Encryption Standard
    (DES) algorithm in Electronic Codebook (ECB) mode. The result is 8 bytes in length ([FIPS46-2]).

    Args:
        k: The 7-byte key to use in the DES cipher.
        d: The 8-byte data block to encrypt.

    Returns:
        bytes: The encrypted data block.
    """
    return DES(DES.key56_to_key64(k)).encrypt(d)


def desl(k, d):  # type: (bytes, bytes) -> bytes
    """Encryption using the DES Long algorithm.

    Indicates the encryption of an 8-byte data item `d` with the 16-byte key `k` using the Data Encryption
    Standard Long (DESL) algorithm. The result is 24 bytes in length.

    `DESL(K, D)` as by MS-NLMP `DESL`_ is computed as follows::

        ConcatenationOf(
            DES(K[0..6], D),
            DES(K[7..13], D),
            DES(ConcatenationOf(K[14..15], Z(5)), D),
        );

    Args:
        k: The key to use for the DES cipher, will be truncated to 16 bytes and then padded to 21 bytes.
        d: The value to run through the DESL algorithm, will be truncated to 8 bytes.

    Returns:
        bytes: The output of the DESL algorithm.

    .. _DESL:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/26c42637-9549-46ae-be2e-90f6f1360193
    """
    k = k[:16].ljust(21, b"\x00")  # Key needs to be stripped at 16 characters and then padded to 21 chars.
    d = d[:8].ljust(8, b"\x00")  # Data need to be at most 8 bytes long.

    b_value = io.BytesIO()

    b_value.write(des(k[:7], d))
    b_value.write(des(k[7:14], d))
    b_value.write(des(k[14:], d))

    return b_value.getvalue()


def hmac_md5(key, data):
    """ Simple wrapper function for a HMAC MD5 digest. """
    return hmac.new(key, data, digestmod=hashlib.md5).digest()


def lmowfv1(password):  # type: (text_type) -> bytes
    """NTLMv1 LMOWFv1 function

    The Lan Manager v1 one way function as documented under `NTLM v1 Authentication`_.

    The pseudo-code for this function is::

        Define LMOWFv1(Passwd, User, UserDom) as
            ConcatenationOf(
                DES(UpperCase(Passwd)[0..6], "KGS!@#$%"),
                DES(UpperCase(Passwd)[7..13], "KGS!@#$%"),
            );

    Args:
        password: The password for the user.

    Returns:
        bytes: The LMv1 one way hash of the user's password.

    .. _NTLM v1 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
    """
    # Fix the password to upper case and pad the length to exactly 14 bytes.
    b_password = to_bytes(password.upper()).ljust(14, b"\x00")[:14]

    b_hash = io.BytesIO()
    for start, end in [(0, 7), (7, 14)]:
        b_hash.write(des(b_password[start:end], b'KGS!@#$%'))

    return b_hash.getvalue()


def ntowfv1(password):  # type: (text_type) -> bytes
    """NTLMv1 NTOWFv1 function

    The NT v1 one way function as documented under `NTLM v1 Authentication`_.

    The pseudo-code for this function is::

        Define NTOWFv1(Passwd, User, UserDom) as MD4(UNICODE(Passwd))

    Args:
        password: The password for the user.

    Returns:
        bytes: The NTv1 one way hash of the user's password.

    .. _NTLM v1 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
    """
    return hashlib.new('md4', to_bytes(password, encoding='utf-16-le')).digest()


def ntowfv2(username, password, domain_name):  # type: (text_type, text_type, Optional[text_type]) -> bytes
    """NTLMv2 NTOWFv2 function

    The NT v2 one way function as documented under `NTLM v2 Authentication`_.

    The pseudo-code for this function is::

        Define NTOWFv2(Passwd, User, UserDom) as

            HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User), UserDom)))

    Args:

    Returns:
        bytes: The NTv2 one way has of the user's credentials.

    .. _NTLM v2 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
    """
    digest = ntowfv1(password)  # ntowfv1 creates the MD4 hash of the user's password.
    b_user = to_bytes(username.upper() + (domain_name or u""), encoding='utf-16-le')
    return hmac_md5(digest, b_user)


lmowfv2 = ntowfv2


def compute_response_v1(flags, response_key_nt, response_key_lm, server_challenge, client_challenge,
                        no_lm_response=True):
    # type: (NegotiateFlags, bytes, bytes, bytes, bytes, bool) -> Tuple[bytes, bytes, bytes]
    """Compute NT and LM Response for NTLMv1.

    Computes the NT and LM Response for NTLMv1 messages. The response is dependent on the flags that were negotiated
    between the client and server.

    The pseudo-code for this function as documented under `NTLM v1 Authentication`_ is::

        Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
            ClientChallenge, Time, ServerName) As

            If (User is set to "" AND Passwd is set to "")
                -- Special case for anonymous authentication
                Set NtChallengeResponseLen to 0
                Set NtChallengeResponseMaxLen to 0
                Set NtChallengeResponseBufferOffset to 0

                Set LmChallengeResponse to Z(1)
            ElseIf
                If (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is set in NegFlg)
                    Set NtChallengeResponse to DESL(ResponseKeyNT,
                        MD5(ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge))[0..7])

                    Set LmChallengeResponse to ConcatenationOf{ClientChallenge, Z(16)}
                Else
                    Set NtChallengeResponse to DESL(ResponseKeyNT, CHALLENGE_MESSAGE.ServerChallenge)

                    If (NoLMResponseNTLMv1 is TRUE)
                        Set LmChallengeResponse to NtChallengeResponse
                    Else
                        Set LmChallengeResponse to DESL(ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge)
                    EndIf
                EndIf
            EndIf

        Set SessionBaseKey to MD4(NTOWF)

    Args:
        flags: The negotiated flags between the initiator and acceptor.
        response_key_nt: The response key computed by :meth:`ntowfv1`.
        response_key_lm: The response key computed by :meth:`lmowfv1`.
        server_challenge: The 8 byte nonce generated by the acceptor.
        client_challenge: The 8 byte nonce generated by the initiator.
        no_lm_response: Whether to compute (True) the `LmChallengeResponse` or not (False) when extended session
            security was not negotiated.

    Returns:
        Tuple[bytes, bytes, bytes]: Returns the NTChallengeResponse, LMChallengeResponse and SessionBaseKey.

    .. _NTLM v1 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
    """
    if flags & NegotiateFlags.anonymous:
        nt_response = b""
        lm_response = b"\x00"
        session_base_key = b""

    else:
        if flags & NegotiateFlags.extended_session_security:
            nt_response = desl(response_key_nt, hashlib.md5(server_challenge + client_challenge[:8]).digest())
            lm_response = client_challenge + (b"\x00" * 16)

        else:
            nt_response = lm_response = desl(response_key_nt, server_challenge)

            if not no_lm_response:
                lm_response = desl(response_key_lm, server_challenge)

        session_base_key = hashlib.new('md4', response_key_nt).digest()

    return nt_response, lm_response, session_base_key


def compute_response_v2(flags, response_key_nt, response_key_lm, server_challenge, client_challenge, time, av_pairs):
    # type: (NegotiateFlags, bytes, bytes, bytes, bytes, FileTime, TargetInfo) -> Tuple[bytes, bytes, bytes]
    """Compute NT and LM Response for NTLMv2.

    Computes the NT and LM Response for NTLMv2 messages. The response is dependent on the flags that were negotiated
    between the client and server.

    The pseudo-code for this function as documented under `NTLM v2 Authentication`_ is::

        Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
            ClientChallenge, Time, ServerName) As

            If (User is set to "" && Passwd is set to "")
                -- Special case for anonymous authentication
                Set NtChallengeResponseLen to 0
                Set NtChallengeResponseMaxLen to 0
                Set NtChallengeResponseBufferOffset to 0

                Set LmChallengeResponse to Z(1)
            Else
                Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4),
                    ServerName, Z(4))

                Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))

                Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)

                Set LmChallengeResponse to ConcatenationOf(
                    HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
                    ClientChallenge)
            EndIf

        Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)

    Args:
        flags: The negotiated flags between the initiator and acceptor.
        response_key_nt: The response key computed by :meth:`ntwofv2`.
        response_key_lm: The response key computed by :meth:`lmowfv2`.
        server_challenge: The 8 byte nonce generated by the acceptor.
        client_challenge: The 8 byte nonce generated by the initiator.
        time: The FileTime to place in the NT hash.
        av_pairs: The TargetInfo AvPairs fields that are placed in the Authenticate message.

    Returns:
        Tuple[bytes, bytes, bytes]: Returns the NTChallengeResponse, LMChallengeResponse and SessionBaseKey.

    .. _NTLM v2 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
    """
    if flags & NegotiateFlags.anonymous:
        nt_response = b""
        lm_response = b"\x00"
        session_base_key = b""

    else:
        temp = b"\x01\x01\x00\x00\x00\x00\x00\x00" + time.pack() + client_challenge + b"\x00\x00\x00\x00" + \
               av_pairs.pack() + b"\x00\x00\x00\x00"
        nt_proof_str = hmac_md5(response_key_nt, server_challenge + temp)

        nt_response = nt_proof_str + temp
        lm_response = hmac_md5(response_key_lm, server_challenge + client_challenge) + client_challenge
        session_base_key = hmac_md5(response_key_nt, nt_proof_str)

    return nt_response, lm_response, session_base_key
