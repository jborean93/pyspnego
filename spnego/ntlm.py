# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging
import os
import socket
import struct

from typing import (
    Optional,
)

from ntlm_auth.gss_channel_bindings import (
    GssChannelBindingsStruct,
)

from ntlm_auth.constants import (
    NegotiateFlags,
)

from ntlm_auth.ntlm import (
    NtlmContext,
)

from ntlm_auth.session_security import (
    SessionSecurity,
)

from spnego.channel_bindings import (
    GssChannelBindings,
)

from spnego._context import (
    ContextProxy,
    ContextReq,
    DEFAULT_REQ,
    split_username,
    UnwrapResult,
    WrapResult,
)

from spnego._ntlm_raw.keys import (
    compute_response_v1,
    compute_response_v2,
    hmac_md5,
    lmowfv1,
    ntowfv1,
    ntowfv2,
    rc4k,
    sealkey,
    signkey,
)

from spnego._ntlm_raw.messages import (
    Authenticate,
    AvFlags,
    AvId,
    Challenge,
    FileTime,
    Negotiate,
    NegotiateFlags,
    TargetInfo,
    Version,
)

from spnego._text import (
    text_type,
    to_text,
)


log = logging.getLogger(__name__)


class NTLMProxy(ContextProxy):

    def __init__(self, username, password, hostname='unspecified', service='host', channel_bindings=None,
                 context_req=DEFAULT_REQ, usage='initiate', protocol='ntlm', is_wrapped=False):
        super(NTLMProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, is_wrapped)

        self._complete = False

        self._domain, self._username = split_username(username)
        self._workstation = None
        self._server_name = None
        self._domain_name = None

        # gss-ntlmssp uses the env var 'LM_COMPAT_LEVEL' to control the NTLM compatibility level. To try and make our
        # NTLM implementation similar in functionality we will also use that behaviour.
        # https://github.com/gssapi/gss-ntlmssp/blob/e498737a96e8832a2cb9141ab1fe51e129185a48/src/gss_ntlmssp.c#L159-L170
        # See the below policy link for more details on what these mean, for now 3 is the sane behaviour.
        # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
        self._lm_compat_level = int(os.environ.get('LM_COMPAT_LEVEL', 3))  # type: int
        if self._lm_compat_level < 0 or self._lm_compat_level > 5:
            raise ValueError("The env var LM_COMPAT_LEVEL is set to %d but needs to be between 0 and 5"
                             % self._lm_compat_level)

        self._context_req = NegotiateFlags(self._context_req) | \
            NegotiateFlags.key_128 | \
            NegotiateFlags.key_56 | \
            NegotiateFlags.key_exch | \
            NegotiateFlags.extended_session_security | \
            NegotiateFlags.always_sign | \
            NegotiateFlags.ntlm | \
            NegotiateFlags.lm_key | \
            NegotiateFlags.request_target | \
            NegotiateFlags.oem | \
            NegotiateFlags.unicode

        if self._lm_compat_level == 0:
            self._context_req &= ~NegotiateFlags.extended_session_security

        elif self._lm_compat_level > 1:
            self._context_req &= ~NegotiateFlags.lm_key

        self._no_lm = self._lm_compat_level > 1
        self._ntlm_v2 = self._lm_compat_level > 2

        # TODO: handle lm_compat_level for acceptor.

        self._negotiate = None
        self._challenge = None
        self._authenticate = None
        self._mic_required = False
        self._session_key = None

    @classmethod
    def available_protocols(cls, context_req=None):
        return [u'ntlm']

    @classmethod
    def iov_available(cls):
        return False

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return u'ntlm'

    @property
    def session_key(self):
        return self._session_key

    def step(self, in_token=None):
        if not self._is_wrapped:
            log.debug("NTLM step input: %s", to_text(base64.b64encode(in_token or b"")))

        out_token = getattr(self, '_step_%s' % self.usage)(in_token=in_token)

        if not self._is_wrapped:
            log.debug("NTLM step output: %s", to_text(base64.b64encode(out_token or b"")))

        return out_token

    def _step_initiate(self, in_token=None):
        if not self._negotiate:
            self._negotiate = Negotiate(self._context_req).pack()
            return self._negotiate
        else:
            challenge = Challenge.unpack(in_token)
            self._challenge = in_token

            # If ClientRequire128bitEncryption and not negotiated, fail 'SEC_E_UNSUPPORTED_FUNCTION'.

            client_challenge = os.urandom(8)
            username = to_text(self._username)
            domain_name = to_text(self._domain)

            workstation = None
            version = None
            if challenge.flags & NegotiateFlags.version:
                version = Version(major=1, minor=1, build=1)
                workstation = to_text(socket.gethostname())

            if self._context_req & NegotiateFlags.anonymous:
                nt_challenge = b""
                lm_challenge = b"\x00"

                key_exchange_key = None

            elif self._ntlm_v2:
                response_key_nt = ntowfv2(username, self.password, domain_name)
                time = challenge.target_info.get(AvId.timestamp, FileTime.now())

                # If Challenge does not contain both ComputerName and DOmainName and integrity or confidentiality
                # raise STATUS_LOGON_FAILURE

                target_info = challenge.target_info.copy()
                if AvId.timestamp in target_info:
                    self._mic_required = True
                    target_info[AvId.flags] = target_info.get(AvId.flags, AvFlags(0)) | AvFlags.mic

                import hashlib
                cbt = hashlib.md5(self._channel_bindings).digest() if self._channel_bindings else b"\x00" * 16
                target_info[AvId.channel_bindings] = cbt

                # If ClientSuppliedTargetName not None:
                #     Add MsvAvTargetName to ClietnSuppliedTargetName
                #     Set MsvAvFlags |= AvFlags.untrusted_spn
                # else:
                target_info[AvId.target_name] = u""

                nt_challenge, lm_challenge, key_exchange_key = compute_response_v2(
                    response_key_nt, challenge.server_challenge, client_challenge, time, target_info)

                if AvId.timestamp in challenge.target_info:
                    lm_challenge = b"\x00" * 24

            else:
                response_key_nt = ntowfv1(self.password)
                response_key_lm = lmowfv1(self.password)
                nt_challenge, lm_challenge, key_exchange_key = compute_response_v1(
                    challenge.flags, response_key_nt, response_key_lm, challenge.server_challenge, client_challenge,
                    no_lm_response=self._no_lm)

            if challenge.flags & NegotiateFlags.key_exch:
                self._session_key = os.urandom(16)
                encrypted_random_session_key = rc4k(key_exchange_key, self._session_key)
            else:
                self._session_key = key_exchange_key
                encrypted_random_session_key = None

            client_singing_key = signkey(challenge.flags, self._session_key, 'initiate')
            server_signing_key = signkey(challenge.flags, self._session_key, 'accept')
            client_sealing_key = sealkey(challenge.flags, self._session_key, 'initiate')
            server_sealing_key = sealkey(challenge.flags, self._session_key, 'accept')

            authenticate = Authenticate(challenge.flags, lm_challenge, nt_challenge, domain_name, username,
                                        workstation, encrypted_random_session_key, version)

            if self._mic_required:
                authenticate.mic = b"\x00" * 16
                temp_auth = authenticate.pack()
                authenticate.mic = hmac_md5(self._session_key, self._negotiate + self._challenge + temp_auth)

            self._authenticate = authenticate.pack()

            self._complete = True

            return self._authenticate

    def _step_accept(self, in_token=None):
        raise NotImplementedError()

    def wrap(self, data, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def unwrap(self, data):
        raise NotImplementedError()

    def unwrap_iov(self, iov):
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def sign(self, data, qop=None):
        raise NotImplementedError()

    def verify(self, data, mic):
        raise NotImplementedError()

    @property
    def _context_attr_map(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a4a41f0d-ca27-44bf-ad1d-6f8c3a3796f2
        return [
            (ContextReq.replay_detect, NegotiateFlags.sign),
            (ContextReq.sequence_detect, NegotiateFlags.sign),
            (ContextReq.confidentiality, NegotiateFlags.seal | NegotiateFlags.key_exch | NegotiateFlags.lm_key |
                NegotiateFlags.extended_session_security),
            (ContextReq.integrity, NegotiateFlags.sign),
            (ContextReq.anonymous, NegotiateFlags.anonymous),
        ]

    @property
    def _requires_mech_list_mic(self):
        return self._mic_required

    def _create_spn(self, service, principal):
        return u"%s/%s" % (service.upper(), principal)

    def _convert_iov_buffer(self, iov):
        pass  # IOV is not used in ntlm-auth.

    def _reset_ntlm_crypto_state(self, outgoing=True):
        raise NotImplementedError()



class NTLMProxy2(ContextProxy):
    """NtlmContext proxy class for ntlm-auth.

    The proxy class for ntlm-auth that exposes this library into a common interface for SPNEGO authentication. This
    context is a pure Python implementation of NTLM but does not offer an acceptor context or fine control over things
    like confidentiality and integrity.

    Args:
        username: The username to authenticate with
        password: The password to authenticate with
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
    """

    def __init__(self, username, password, channel_bindings=None, context_req=DEFAULT_REQ, is_wrapped=False):
        # type: (text_type, text_type, Optional[GssChannelBindings], ContextReq, bool) -> None
        super(NTLMProxy, self).__init__(username, password, None, None, channel_bindings, context_req, 'initiate',
                                        'ntlm', is_wrapped)

        domain, username = split_username(self.username)
        self._context = NtlmContext(username, password, domain=domain, cbt_data=self._channel_bindings)

    @classmethod
    def available_protocols(cls, context_req=None):
        return [u'ntlm']

    @classmethod
    def iov_available(cls):
        return False

    @property
    def complete(self):
        return self._context.complete

    @property
    def negotiated_protocol(self):
        return u'ntlm'

    @property
    def session_key(self):
        # session_key was only recently added in ntlm-auth, we have the fallback to the non-public interface for
        # older versions where we know this still works.
        # TODO: Remove getattr when ntlm-auth>=1.4.0.
        return getattr(self._context, 'session_key', self._context._session_security.exported_session_key)

    def step(self, in_token=None):
        out_token = self._context.step(input_token=in_token)

        if not self._is_wrapped:
            log.debug("NTLM step input: %s", to_text(base64.b64encode(in_token or b"")))

        if self.complete:
            # ntlm-auth negotiate_flags set were the original flags the client sent and not what the server ultimately
            # accepted. ntlm-auth 1.5.0 fixed this so we check for a new value added then to determine where to get the
            # flags from.
            # TODO: Remove hasattr when ntlm-auth>=1.5.0
            if hasattr(self._context, 'reset_rc4_state'):
                flags = self._context.negotiate_flags
            else:
                flags = struct.unpack("<I", self._context._authenticate_message.negotiate_flags)[0]

            integrity = False
            if flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL:
                self._context_attr |= ContextReq.confidentiality
                integrity = True

            elif flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN:
                integrity = True

            if integrity:
                self._context_attr |= ContextReq.integrity | ContextReq.replay_detect | ContextReq.sequence_detect

        if not self._is_wrapped:
            log.debug("ntlm-auth step output; %s", to_text(base64.b64encode(out_token or b"")))

        return out_token

    def wrap(self, data, encrypt=True, qop=None):
        if not encrypt:
            raise NotImplementedError("NtlmContext does not support non-confidential wrapping")
        if qop:
            raise NotImplementedError("NtlmContext does not support custom qop value")

        is_encrypted = bool(self.context_req & ContextReq.confidentiality)
        return WrapResult(data=self._context.wrap(data), encrypted=is_encrypted)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def unwrap(self, data):
        is_encrypted = bool(self.context_req & ContextReq.confidentiality)
        return UnwrapResult(data=self._context.unwrap(data), encrypted=is_encrypted, qop=0)

    def unwrap_iov(self, iov):
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def sign(self, data, qop=None):
        if self.context_req & ContextReq.integrity == 0:
            raise NotImplementedError("No integrity")

        # ntlm-auth only added the sign function in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        # TODO: Remove getattr when ntlm-auth>=1.5.0.
        return getattr(self._context, 'sign', self._context._session_security._get_signature)(data)

    def verify(self, data, mic):
        # ntlm-auth only added the verify function in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        # TODO: Remove gettr when ntlm-auth>=1.5.0
        getattr(self._context, 'verify', self._context._session_security._verify_signature)(data, mic)

        return 0

    @property
    def _context_attr_map(self):
        return []  # ntlm-auth doesn't natively use these flags so we don't need to translate them.

    @property
    def _requires_mech_list_mic(self):
        # ntlm-auth only added the mic_present attribute in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        # TODO: remove hasattr when ntlm-auth>=1.5.0.
        if hasattr(self._context, 'mic_present'):
            return self._context.mic_present

        if self._context._authenticate_message:
            return bool(self._context._authenticate_message.mic)

    def _create_spn(self, service, principal):
        return u""  # SPNs are not used in ntlm-auth.

    def _convert_iov_buffer(self, iov):
        pass  # IOV is not used in ntlm-auth.

    def _convert_channel_bindings(self, bindings):
        cbt = GssChannelBindingsStruct()
        cbt[cbt.INITIATOR_ADDTYPE] = bindings.initiator_addrtype
        cbt[cbt.INITIATOR_ADDRESS] = bindings.initiator_address
        cbt[cbt.ACCEPTOR_ADDRTYPE] = bindings.acceptor_addrtype
        cbt[cbt.ACCEPTOR_ADDRESS] = bindings.acceptor_address
        cbt[cbt.APPLICATION_DATA] = bindings.application_data

        return cbt

    def _reset_ntlm_crypto_state(self, outgoing=True):
        # ntlm-auth only added the reset_rc4_state method in v1.5.0. We try and use that method if present and fallback
        # to an internal mechanism we know will work with older versions.
        # TODO: Remove hasattr when ntlm-auth>=1.5.0
        if hasattr(self._context, 'reset_rc4_state'):
            self._context.reset_rc4_state(outgoing=outgoing)
        else:
            existing_ss = self._context._session_security

            # Can't just copy the keys, we need to derive the RC4 handle from the session_key so just recreate the obj.
            new_ss = SessionSecurity(existing_ss.negotiate_flags, self.session_key)
            new_ss.outgoing_seq_num = existing_ss.outgoing_seq_num
            new_ss.incoming_seq_num = existing_ss.incoming_seq_num

            self._context._session_security = new_ss
