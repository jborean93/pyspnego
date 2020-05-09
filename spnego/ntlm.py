# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import hashlib
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
    Version,
)

from spnego._text import (
    to_text,
)

log = logging.getLogger(__name__)


class NTLMProxy(ContextProxy):

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None,
                 context_req=ContextReq.default, usage='initiate', protocol='ntlm', options=0, is_wrapped=False):
        super(NTLMProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, options, is_wrapped)

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
            NegotiateFlags.always_sign | \
            NegotiateFlags.ntlm | \
            NegotiateFlags.request_target | \
            NegotiateFlags.oem | \
            NegotiateFlags.unicode

        if self._lm_compat_level != 0:
            self._context_req |= NegotiateFlags.extended_session_security

        # This should be possible but cannot get wrapping to work against a MS server.
        # if self._lm_compat_level == 1:
        #     self._context_req |= NegotiateFlags.lm_key

        self._no_lm = self._lm_compat_level > 1
        self._ntlm_v2 = self._lm_compat_level > 2

        # TODO: handle lm_compat_level for acceptor.

        self._negotiate_msg = None
        self._challenge_msg = None
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
    def available_protocols(cls, options=None):
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

        if self._complete:
            in_usage = 'accept' if self.usage == 'initiate' else 'initiate'
            self._sign_key_out = signkey(self._context_attr, self._session_key, self.usage)
            self._sign_key_in = signkey(self._context_attr, self._session_key, in_usage)

            # Found a vague reference in MS-NLMP that states if NTLMv2 authentication was not used then only 1 key is
            # used for sealing. This seems to reference when NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY is not set and
            # not NTLMv2 messages itself.
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d1c86e81-eb66-47fd-8a6f-970050121347
            if self._context_attr & NegotiateFlags.extended_session_security:
                self._handle_out = rc4init(sealkey(self._context_attr, self._session_key, self.usage))
                self._handle_in = rc4init(sealkey(self._context_attr, self._session_key, in_usage))
            else:
                self._handle_out = self._handle_in = rc4init(sealkey(self._context_attr, self._session_key,
                                                                     self.usage))

        return out_token

    def _step_initiate(self, in_token=None):
        # TODO: Find a better way for this
        if not self._negotiate_msg:
            self._negotiate_msg = Negotiate(self._context_req).pack()
            return self._negotiate_msg

        else:
            challenge = Challenge.unpack(in_token)

            # If ClientRequire128bitEncryption and not negotiated, fail 'SEC_E_UNSUPPORTED_FUNCTION'.

            auth_kwargs = {
                'domain_name': self._domain,
                'username': self._username
            }

            if challenge.flags & NegotiateFlags.version:
                auth_kwargs['version'] = Version.get_current()
                auth_kwargs['workstation'] = to_text(socket.gethostname()).upper()

            nt_challenge, lm_challenge, key_exchange_key = self._compute_response(challenge, self._username,
                                                                                  self.password, self._domain)
            if challenge.flags & NegotiateFlags.key_exch:
                self._session_key = os.urandom(16)
                auth_kwargs['encrypted_session_key'] = rc4k(key_exchange_key, self._session_key)

            else:
                self._session_key = key_exchange_key

            authenticate = Authenticate(challenge.flags, lm_challenge, nt_challenge, **auth_kwargs)

            if self._mic_required:
                authenticate.mic = b"\x00" * 16
                temp_auth = authenticate.pack()
                authenticate.mic = hmac_md5(self._session_key, self._negotiate_msg + in_token + temp_auth)

                self._negotiate_msg = None   # No longer need to keep the previous messages around.

            self._context_attr = authenticate.flags
            self._complete = True

            return authenticate.pack()

    def _step_accept(self, in_token=None):
        # TODO: Clean this up majorly
        if not self._negotiate_msg:
            self._negotiate_msg = in_token

            negotiate = Negotiate.unpack(in_token)

            flags = negotiate.flags | NegotiateFlags.request_target | NegotiateFlags.ntlm | \
                NegotiateFlags.always_sign | NegotiateFlags.target_info | NegotiateFlags.target_type_server

            # Make sure either UNICODE or OEM is set, not both.
            if flags & NegotiateFlags.unicode:
                flags &= ~NegotiateFlags.oem
            elif flags & NegotiateFlags.oem == 0:
                raise ValueError("No flags were set, check gss-ntlmssp for this behaviour")

            # Make sure either ESS or LM_Key is set, not both.
            if flags & NegotiateFlags.extended_session_security:
                flags &= ~NegotiateFlags.lm_key

            server_challenge = os.urandom(8)
            self._server_nonce = server_challenge
            target_name = to_text(socket.gethostname()).upper()

            target_info = TargetInfo()
            target_info[AvId.nb_computer_name] = target_name
            target_info[AvId.nb_domain_name] = u"WORKSTATION"
            target_info[AvId.dns_computer_name] = to_text(socket.getfqdn())
            target_info[AvId.timestamp] = FileTime.now()
            self._server_target_info = target_info

            challenge = Challenge(flags, server_challenge, target_name=target_name, target_info=target_info)
            self._challenge_msg = challenge.pack(encoding='windows-1252')

            return self._challenge_msg

        else:
            auth = Authenticate.unpack(in_token)

            if not auth.username and not auth.nt_challenge_response and (not auth.lm_challenge_response or
                                                                         auth.lm_challenge_response == b"\x00"):

                # Anonymous user.
                raise Exception("Anonymous user")

            else:
                # TODO: Lookup NTLM_USER_FILE for creds
                expected_user = u"vagrant-domain@DOMAIN.LOCAL"

                if auth.username.upper() != expected_user.upper():
                    raise Exception("Auth error, no matching user")

                actual_pass = u"VagrantPass1"

                if len(auth.nt_challenge_response) > 24:
                    client_challenge = auth.nt_challenge_response[32:40]
                elif auth.flags & NegotiateFlags.extended_session_security:
                    client_challenge = auth.lm_challenge_response[:8]
                else:
                    client_challenge = None

                ntow = ntowfv2(expected_user, actual_pass, None)

                b_challenge = auth.nt_challenge_response[16:]
                time = FileTime.unpack(b_challenge[8:16])
                target_info = TargetInfo.unpack(b_challenge[28:-4])

                expected_nt, expected_lm, key_exchange_key = compute_response_v2(
                    ntow, self._server_nonce, client_challenge, time, target_info)

                if expected_nt != auth.nt_challenge_response:
                    raise Exception("Invalid credential")

                if AvId.timestamp not in target_info and expected_lm != auth.lm_challenge_response:
                    raise Exception("Invalid lm hash")

                if auth.flags & NegotiateFlags.key_exch:
                    self._session_key = rc4k(key_exchange_key, auth.encrypted_random_session_key)
                else:
                    self._session_key = key_exchange_key

                if target_info.get(AvId.flags, 0) & AvFlags.mic:
                    temp_auth = in_token[:64] + (b"\x00" * 16) + in_token[80:]
                    expected_mic = hmac_md5(self._session_key, self._negotiate_msg + self._challenge_msg + temp_auth)

                    if auth.mic != expected_mic:
                        raise Exception("Invalid MIC")

                self._context_attr = auth.flags

                self._complete = True
                self._negotiate_msg = None
                self._challenge_msg = None

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
        if self._context_attr & NegotiateFlags.extended_session_security:
            num = self.__seq_num_in
            self.__seq_num_in += 1

        else:
            num = self.__seq_num_out
            self.__seq_num_out += 1

        return num

    @property
    def _seq_num_out(self):
        num = self.__seq_num_out
        self.__seq_num_out += 1
        return num

    def _compute_response(self, challenge, username, password, domain):
        # type: (Challenge, text_type, text_type) -> Tuple[bytes, bytes, bytes]
        """ Compute the NT and LM responses and the key exchange key. """
        client_challenge = os.urandom(8)

        if self._context_req & NegotiateFlags.anonymous:
            return b"", b"\x00", b""

        elif self._ntlm_v2:
            response_key_nt = ntowfv2(username, password, domain)

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
            response_key_nt = ntowfv1(password)
            response_key_lm = lmowfv1(password)

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
