# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import hashlib
import io
import logging
import os
import socket

from spnego._context import (
    ContextProxy,
    ContextReq,
    split_username,
    UnwrapResult,
    WrapResult,
)

from spnego._ntlm_raw.crypto import (
    compute_response_v1,
    compute_response_v2,
    hmac_md5,
    lmowfv1,
    ntowfv1,
    ntowfv2,
    rc4init,
    rc4k,
    sealkey,
    signkey,
)

from spnego._ntlm_raw.security import (
    seal,
    sign,
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
)

from spnego._text import (
    to_text,
)

from spnego._version import (
    get_ntlm_version,
)


log = logging.getLogger(__name__)


class NTLMProxy(ContextProxy):

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None,
                 context_req=ContextReq.default, usage='initiate', protocol='ntlm', is_wrapped=False):
        super(NTLMProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, is_wrapped)

        self._complete = False

        self._domain, self._username = split_username(username)

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

        self._mic_buffer = io.BytesIO()
        self._mic_required = False

        # Crypto state for signing and sealing.
        self._session_key = None
        self._sign_key_out = None
        self._sign_key_in = None
        self._handle_out = None
        self._handle_in = None
        self.__seq_num_in = 0
        self.__seq_num_out = 0

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

        self._mic_buffer.write(in_token or b"")

        out_token = getattr(self, '_step_%s' % self.usage)(in_token=in_token)

        if not self._is_wrapped:
            log.debug("NTLM step output: %s", to_text(base64.b64encode(out_token or b"")))

        if self._complete:
            in_usage = 'accept' if self.usage == 'initiate' else 'initiate'
            self._sign_key_out = signkey(self._context_attr, self._session_key, self.usage)
            self._sign_key_in = signkey(self._context_attr, self._session_key, in_usage)

            self._handle_out = rc4init(sealkey(self._context_attr, self._session_key, self.usage))
            self._handle_in = rc4init(sealkey(self._context_attr, self._session_key, in_usage))

        elif out_token:
            self._mic_buffer.write(out_token)

        return out_token

    def _step_initiate(self, in_token=None):
        # TODO: Find a better way for this
        if not in_token:
            return Negotiate(self._context_req).pack()

        else:
            challenge = Challenge.unpack(in_token)

            # If ClientRequire128bitEncryption and not negotiated, fail 'SEC_E_UNSUPPORTED_FUNCTION'.

            auth_kwargs = {
                'domain_name': self._domain,
                'username': self._username
            }

            if challenge.flags & NegotiateFlags.version:
                auth_kwargs['version'] = get_ntlm_version()
                auth_kwargs['workstation'] = to_text(socket.gethostname()).upper()

            nt_challenge, lm_challenge, key_exchange_key = self._compute_response(challenge)
            if challenge.flags & NegotiateFlags.key_exch:
                self._session_key = os.urandom(16)
                auth_kwargs['encrypted_session_key'] = rc4k(key_exchange_key, self._session_key)

            else:
                self._session_key = key_exchange_key

            authenticate = Authenticate(challenge.flags, lm_challenge, nt_challenge, **auth_kwargs)

            if self._mic_required:
                authenticate.mic = b"\x00" * 16
                temp_auth = authenticate.pack()
                authenticate.mic = hmac_md5(self._session_key, self._mic_buffer.getvalue() + temp_auth)

                self._mic_buffer = None  # No longer need to keep the previous messages around.

            self._context_attr = authenticate.flags
            self._complete = True

            return authenticate.pack()

    def _step_accept(self, in_token=None):
        raise NotImplementedError()

    def wrap(self, data, encrypt=True, qop=None):
        # gss-ntlmssp and SSPI always seals the data even if integrity wasn't negotiated.
        # TODO: verify if gss-ntlmssp fails for the above, SSPI doesn't due to NTLMSSP_NEGOTIATE_ALWAYS_SING
        msg, signature = seal(self._context_attr, self._handle_out, self._sign_key_out, self._seq_num_out,
                              data)

        return WrapResult(data=signature + msg, encrypted=True)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        # While this technically works on SSPI by passing multiple data buffers we can achieve the same thing with
        # wrap. Because this context proxy is meant to replicate gss-ntlmssp which doesn't support IOV in NTLM we just
        # fail here.
        # TODO: Figure out the NotImplementedError() equivalent in GSSAPI.
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def unwrap(self, data):
        signature = data[:16]
        msg = self._handle_in.update(data[16:])
        self.verify(msg, signature)

        return UnwrapResult(data=msg, encrypted=True, qop=0)

    def unwrap_iov(self, iov):
        raise NotImplementedError("NtlmContext does not offer IOV wrapping")

    def sign(self, data, qop=None):
        return sign(self._context_attr, self._handle_out, self._sign_key_out, self._seq_num_out, data)

    def verify(self, data, mic):
        expected_sig = sign(self._context_attr, self._handle_in, self._sign_key_in, self._seq_num_in, data)

        if expected_sig != mic:
            raise Exception("Invalid signature detected")

        return 0

    @property
    def _context_attr_map(self):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a4a41f0d-ca27-44bf-ad1d-6f8c3a3796f2
        return [
            (ContextReq.replay_detect, NegotiateFlags.sign),
            (ContextReq.sequence_detect, NegotiateFlags.sign),
            (ContextReq.confidentiality, NegotiateFlags.seal),
            (ContextReq.integrity, NegotiateFlags.sign),
            (ContextReq.anonymous, NegotiateFlags.anonymous),
        ]

    @property
    def _requires_mech_list_mic(self):
        # If called before the Authenticate message has been created it force the MIC to be present on the message.
        # When called after the Auth message it will return whether the MIC was generated or not.
        if not self._complete:
            self._mic_required = True
            return False

        return self._mic_required

    @property
    def _seq_num_in(self):
        num = self.__seq_num_in
        self.__seq_num_in += 1
        return num

    @property
    def _seq_num_out(self):
        num = self.__seq_num_out
        self.__seq_num_out += 1
        return num

    def _compute_response(self, challenge):  # type: (Challenge) -> Tuple[bytes, bytes, bytes]
        """ Compute the NT and LM responses and the key exchange key. """
        client_challenge = os.urandom(8)

        if self._context_req & NegotiateFlags.anonymous:
            return b"", b"\x00", b""

        elif self._ntlm_v2:
            response_key_nt = ntowfv2(self._username, self.password, self._domain)

            target_info = challenge.target_info.copy() if challenge.target_info else TargetInfo()

            if AvId.timestamp in target_info:
                time = target_info[AvId.timestamp]
                self._mic_required = True

            else:
                time = FileTime.now()

            # If Challenge does not contain both ComputerName and DomainName and integrity or confidentiality
            # if (self.context_req & ContextReq.integrity or self.context_req & ContextReq.confidentiality) and \
            #        AvId.dns_computer_name not in target_info and AvId.dns_domain_name not in target_info:
            #    raise Exception("STATUS_LOGON_FAILURE")

            cbt = hashlib.md5(self._channel_bindings).digest() if self._channel_bindings else b"\x00" * 16
            target_info[AvId.channel_bindings] = cbt

            # TODO: Find a way to pass in untrusted SPN.
            target_info[AvId.target_name] = self.spn or u""

            if self._mic_required:
                target_info[AvId.flags] = target_info.get(AvId.flags, AvFlags(0)) | AvFlags.mic

            nt_challenge, lm_challenge, key_exchange_key = compute_response_v2(
                response_key_nt, challenge.server_challenge, client_challenge, time, target_info)

            if self._mic_required:
                lm_challenge = b"\x00" * 24

            return nt_challenge, lm_challenge, key_exchange_key

        else:
            response_key_nt = ntowfv1(self.password)
            response_key_lm = lmowfv1(self.password)

            return compute_response_v1(challenge.flags, response_key_nt, response_key_lm, challenge.server_challenge,
                                       client_challenge, no_lm_response=self._no_lm)

    def _create_spn(self, service, principal):
        if not service and not principal:
            return

        return u"%s/%s" % (service or u"host", principal or u"unspecified")

    def _convert_iov_buffer(self, iov):
        pass  # IOV is not used in this NTLM provider like gss-ntlmssp.

    def _reset_ntlm_crypto_state(self, outgoing=True):
        self._handle_out.reset() if outgoing else self._handle_in.reset()
