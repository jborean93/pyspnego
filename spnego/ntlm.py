# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

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

from spnego._text import (
    text_type,
)

# TODO: Look up internalising all this into this library instead of using ntlm-auth


class NTLMProxy(ContextProxy):
    """NtlmContext proxy class for ntlm-auth.

    The proxy class for ntlm-auth that exposes this library into a common interface for SPNEGO authentication. This
    context is a pure Python implementation of NTLM but does not offer an acceptor context or fine control over things
    like confidentiality and integrity.

    Args:
        username: The username to authenticate with
        password: The password to authenticate with
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
    """

    def __init__(self, username, password, channel_bindings=None, context_req=DEFAULT_REQ):
        # type: (text_type, text_type, Optional[GssChannelBindings], ContextReq) -> None
        super(NTLMProxy, self).__init__(username, password, None, None, channel_bindings, context_req, 'initiate',
                                        'ntlm')

        domain, username = split_username(self.username)
        self._context = NtlmContext(username, password, domain=domain, cbt_data=self.channel_bindings)

    @classmethod
    def available_protocols(cls, feature_flags=0):
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

    @property
    def requires_mech_list_mic(self):
        # ntlm-auth only added the mic_present attribute in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        # TODO: remove hasattr when ntlm-auth>=1.5.0.
        if hasattr(self._context, 'mic_present'):
            return self._context.mic_present

        if self._context._authenticate_message:
            return bool(self._context._authenticate_message.mic)

    def create_spn(self, service, principal):
        return u""  # SPNs are not used in ntlm-auth.

    def step(self, in_token=None):
        out_token = self._context.step(input_token=in_token)

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
                self.context_attr |= ContextReq.confidentiality
                integrity = True

            elif flags & NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN:
                integrity = True

            if integrity:
                self.context_attr |= ContextReq.integrity | ContextReq.replay_detect | ContextReq.sequence_detect

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

    def convert_channel_bindings(self, bindings):
        cbt = GssChannelBindingsStruct()
        cbt[cbt.INITIATOR_ADDTYPE] = bindings.initiator_addrtype
        cbt[cbt.INITIATOR_ADDRESS] = bindings.initiator_address
        cbt[cbt.ACCEPTOR_ADDRTYPE] = bindings.acceptor_addrtype
        cbt[cbt.ACCEPTOR_ADDRESS] = bindings.acceptor_address
        cbt[cbt.APPLICATION_DATA] = bindings.application_data

        return cbt

    def reset_ntlm_crypto_state(self, outgoing=True):
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
