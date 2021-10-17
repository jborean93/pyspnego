# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import os
import socket
import typing

from spnego._context import (
    ContextProxy,
    ContextReq,
    IOVUnwrapResult,
    IOVWrapResult,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
    split_username,
)
from spnego._ntlm_raw.crypto import (
    RC4Handle,
    compute_response_v1,
    compute_response_v2,
    hmac_md5,
    lmowfv1,
    md5,
    ntowfv1,
    ntowfv2,
    rc4init,
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
    NTClientChallengeV2,
    TargetInfo,
    Version,
)
from spnego._ntlm_raw.security import seal, sign
from spnego._text import to_text
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import (
    BadBindingsError,
    BadMICError,
    ErrorCode,
    InvalidTokenError,
    NegotiateOptions,
    OperationNotAvailableError,
    SpnegoError,
    UnsupportedQop,
)
from spnego.iov import IOVBuffer

log = logging.getLogger(__name__)


def _get_credential_file() -> typing.Optional[str]:
    """Get the path to the NTLM credential store.

    Returns the path to the NTLM credential store specified by the environment variable `NTLM_USER_FILE`.

    Returns:
        Optional[bytes]: The path to the NTLM credential file or None if not set or found.
    """
    user_file_path = os.environ.get('NTLM_USER_FILE', None)
    if not user_file_path:
        return None

    file_path = to_text(user_file_path, encoding='utf-8')
    if os.path.isfile(file_path):
        return file_path

    return None


def _get_credential(
    store: str,
    domain: typing.Optional[str] = None,
    username: typing.Optional[str] = None,
) -> typing.Tuple[str, str, bytes, bytes]:
    """Look up NTLM credentials from the common flat file.

    Retrieves the LM and NT hash for use with authentication or validating a credential from an initiator.

    Each line in the store can be in the Heimdal format `DOMAIN:USER:PASSWORD` like::

        testdom:testuser:Password01
        :testuser@TESTDOM.COM:Password01

    Or it can use the `smbpasswd`_ file format `USERNAME:UID:LM_HASH:NT_HASH:ACCT_FLAGS:TIMESTAMP` like::

        testuser:1000:278623D830DABE161104594F8C2EF12B:C3C6F4FD8A02A6C1268F1A8074B6E7E0:[U]:LCT-1589398321
        TESTDOM\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321
        testuser@TESTDOM.COM:1000:00000000000000000000000000000000:8ADB9B997580D69E69CAA2BBB68F4697:[U]:LCT-1589398321

    While only the `USERNAME`, `LM_HASH`, and `NT_HASH` fields are used, the colons are still required to differentiate
    between the 2 formats. See `ntlm hash generator`_ for ways to generate the `LM_HASH` and `NT_HASH`.

    The username is case insensitive but the format of the domain and user part must match up with the value used as
    the username specified by the caller.

    While each line can use a different format, it is recommended to stick to 1 throughout the file.

    The same env var and format can also be read with gss-ntlmssp.

    Args:
        store: The credential store to lookup the credential from.
        domain: The domain for the user to get the credentials for. Should be `None` for a user in the UPN form.
        username: The username to get the credentials for. If omitted then the first entry in the store is used.

    Returns:
        Tuple[str, str, bytes, bytes]: The domain, username, LM, and NT hash of the user specified.

    .. _smbpasswd:
        https://www.samba.org/samba/docs/current/man-html/smbpasswd.5.html

    .. _ntlm hash generator:
        https://asecuritysite.com/encryption/lmhash
    """
    if not store:
        raise OperationNotAvailableError(context_msg="Retrieving NTLM store without NTLM_USER_FILE set to a filepath")

    domain = domain or ""

    def store_lines(text):
        for line in text.splitlines():
            line_split = line.split(':')

            if len(line_split) == 3:
                yield line_split[0], line_split[1], line_split[2], None, None

            elif len(line_split) == 6:
                domain_entry, user_entry = split_username(line_split[0])
                lm_entry = base64.b16decode(line_split[2].upper())
                nt_entry = base64.b16decode(line_split[3].upper())

                yield domain_entry or "", user_entry, None, lm_entry, nt_entry

    with open(store, mode='rb') as fd:
        cred_text = fd.read().decode()

        for line_domain, line_user, line_password, lm_hash, nt_hash in store_lines(cred_text):
            if not username or (username.upper() == line_user.upper() and domain.upper() == line_domain.upper()):
                # The Heimdal format uses the password so if the LM or NT hash isn't set generate it ourselves.
                if not lm_hash:
                    lm_hash = lmowfv1(line_password)
                if not nt_hash:
                    nt_hash = ntowfv1(line_password)

                # Favour the explicit username/password value, otherwise use what was in the credential file.
                if not username:
                    username = line_user

                if not domain:
                    domain = line_domain or None

                return domain, username, lm_hash, nt_hash

        else:
            raise SpnegoError(ErrorCode.failure, context_msg="Failed to find any matching credential in "
                                                             "NTLM_USER_FILE credential store.")


def _get_workstation() -> typing.Optional[str]:
    """Get the current workstation name.

    This gets the current workstation name that respects `NETBIOS_COMPUTER_NAME`. The env var is used by the library
    that gss-ntlmssp calls and makes sure that this Python implementation is a closer in its behaviour.

    Returns:
        Optional[str]: The workstation to supply in the NTLM authentication message or None.
    """
    if 'NETBIOS_COMPUTER_NAME' in os.environ:
        workstation = os.environ['NETBIOS_COMPUTER_NAME']

    else:
        workstation = socket.gethostname().upper()

    # An empty workstation should be None so we don't set it in the message.
    return to_text(workstation) if workstation else None


class _NTLMCredential:

    def __init__(
        self,
        domain: typing.Optional[str] = None,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
    ) -> None:
        if password:
            self.domain = domain
            self.username = username
            self.lm_hash = lmowfv1(password)
            self.nt_hash = ntowfv1(password)
            self._store = 'explicit'

        else:
            self._store = _get_credential_file()
            self.domain, self.username, self.lm_hash, self.nt_hash = _get_credential(self._store, domain, username)


class NTLMProxy(ContextProxy):
    """A context wrapper for a Python managed NTLM context.

    This is a context that can be used on Linux to generate NTLM without any system dependencies.
    """

    def __init__(
        self,
        username: str,
        password: str,
        hostname: typing.Optional[str] = None,
        service: typing.Optional[str] = None,
        channel_bindings: typing.Optional[GssChannelBindings] = None,
        context_req: ContextReq = ContextReq.default,
        usage: str = 'initiate',
        protocol: str = 'ntlm',
        options: NegotiateOptions = NegotiateOptions.none,
        _is_wrapped: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        super(NTLMProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, options, _is_wrapped)

        self._complete = False
        self._credential: typing.Optional[_NTLMCredential] = None

        # Set the default flags, these might change depending on the LM_COMPAT_LEVEL set.
        self._context_req = self._context_req | \
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

        # gss-ntlmssp uses the env var 'LM_COMPAT_LEVEL' to control the NTLM compatibility level. To try and make our
        # NTLM implementation similar in functionality we will also use that behaviour.
        # https://github.com/gssapi/gss-ntlmssp/blob/e498737a96e8832a2cb9141ab1fe51e129185a48/src/gss_ntlmssp.c#L159-L170
        # See the below policy link for more details on what these mean, for now 3 is the sane behaviour.
        # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
        lm_compat_level = int(os.environ.get('LM_COMPAT_LEVEL', 3))
        if lm_compat_level < 0 or lm_compat_level > 5:
            raise SpnegoError(ErrorCode.failure, context_msg="Invalid LM_COMPAT_LEVEL %d, must be between 0 and 5"
                                                             % lm_compat_level)

        if lm_compat_level == 0:
            self._context_req &= ~NegotiateFlags.extended_session_security

        if self.usage == 'initiate':
            domain, user = split_username(self.username)
            self._credential = _NTLMCredential(domain=domain, username=user, password=self.password)

            self._lm = lm_compat_level < 2
            self._nt_v1 = lm_compat_level < 3
            self._nt_v2 = lm_compat_level > 2

            if lm_compat_level > 1:
                self._context_req &= ~NegotiateFlags.lm_key

        else:
            self._lm = lm_compat_level < 4
            self._nt_v1 = lm_compat_level < 5
            self._nt_v2 = True

            # Make sure that the credential file is set and exists
            if not _get_credential_file():
                raise OperationNotAvailableError(context_msg="Retrieving NTLM store without NTLM_USER_FILE set to a "
                                                             "filepath")

        self._temp_msg = {
            'negotiate': None,
            'challenge': None,
        }
        self._mic_required = False

        # Crypto state for signing and sealing.
        self._session_key: typing.Optional[bytes] = None
        self._sign_key_out: typing.Optional[bytes] = None
        self._sign_key_in: typing.Optional[bytes] = None
        self._handle_out: typing.Optional[RC4Handle] = None
        self._handle_in: typing.Optional[RC4Handle] = None
        self.__seq_num_in = 0
        self.__seq_num_out = 0

    @classmethod
    def available_protocols(cls, options: typing.Optional[NegotiateOptions] = None) -> typing.List[str]:
        return ['ntlm']

    @classmethod
    def iov_available(cls) -> bool:
        return False

    @property
    def client_principal(self) -> typing.Optional[str]:
        if self.usage == 'accept' and self.complete:
            domain_part = self._credential.domain + '\\' if self._credential.domain else ''
            return '%s%s' % (domain_part, self._credential.username)

    @property
    def complete(self) -> bool:
        return self._complete

    @property
    def negotiated_protocol(self) -> typing.Optional[str]:
        return 'ntlm'

    @property
    def session_key(self) -> bytes:
        return self._session_key

    def step(self, in_token: typing.Optional[bytes] = None) -> typing.Optional[bytes]:
        if not self._is_wrapped:
            log.debug("NTLM step input: %s", base64.b64encode(in_token or b"").decode())

        out_token = getattr(self, '_step_%s' % self.usage)(in_token=in_token)

        if not self._is_wrapped:
            log.debug("NTLM step output: %s", base64.b64encode(out_token or b"").decode())

        if self._complete:
            self._temp_msg = None  # Clear out any temp data we still have stored.

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

    def _step_initiate(self, in_token: typing.Optional[bytes] = None) -> bytes:
        if not self._temp_msg['negotiate']:
            negotiate_msg = Negotiate(self._context_req)
            self._temp_msg['negotiate'] = negotiate_msg
            return negotiate_msg.pack()

        challenge = Challenge.unpack(in_token)

        auth_kwargs = {
            'domain_name': self._credential.domain,
            'username': self._credential.username,
        }

        if challenge.flags & NegotiateFlags.version:
            auth_kwargs['version'] = Version.get_current()
            auth_kwargs['workstation'] = _get_workstation()

        nt_challenge, lm_challenge, key_exchange_key = self._compute_response(challenge, self._credential)

        if challenge.flags & NegotiateFlags.key_exch:
            # This is only documented on the server side for MS-NLMP but is also valid for the client. The actual
            # session key is the KeyExchangeKey like normal unless sign or seal is negotiated.

            if challenge.flags & NegotiateFlags.sign or challenge.flags & NegotiateFlags.seal:
                self._session_key = os.urandom(16)
                auth_kwargs['encrypted_session_key'] = rc4k(key_exchange_key, self._session_key)

            else:
                self._session_key = key_exchange_key
                auth_kwargs['encrypted_session_key'] = b"\x00"  # Must be set to some value but this can be anything.

        else:
            self._session_key = key_exchange_key

        authenticate = Authenticate(challenge.flags, lm_challenge, nt_challenge, **auth_kwargs)

        if self._mic_required:
            authenticate.mic = self._calculate_mic(self._temp_msg['negotiate'].pack(), in_token, authenticate.pack())

        self._context_attr = authenticate.flags
        self._complete = True

        return authenticate.pack()

    def _step_accept(self, in_token: typing.Optional[bytes] = None) -> bytes:
        if not self._temp_msg['negotiate']:
            return self._step_accept_negotiate(in_token)

        else:
            return self._step_accept_authenticate(in_token)

    def _step_accept_negotiate(self, token: bytes) -> bytes:
        """ Process the Negotiate message from the initiator. """
        negotiate = Negotiate.unpack(token)

        flags = negotiate.flags | NegotiateFlags.request_target | NegotiateFlags.ntlm | \
            NegotiateFlags.always_sign | NegotiateFlags.target_info | NegotiateFlags.target_type_server

        # Make sure either UNICODE or OEM is set, not both.
        if flags & NegotiateFlags.unicode:
            flags &= ~NegotiateFlags.oem
        elif flags & NegotiateFlags.oem == 0:
            raise SpnegoError(ErrorCode.failure, context_msg="Neither NEGOTIATE_OEM or NEGOTIATE_UNICODE flags were "
                                                             "set, cannot derive encoding for text fields")

        if flags & NegotiateFlags.extended_session_security:
            flags &= ~NegotiateFlags.lm_key

        server_challenge = os.urandom(8)
        target_name = to_text(socket.gethostname()).upper()

        target_info = TargetInfo()
        target_info[AvId.nb_computer_name] = target_name
        target_info[AvId.nb_domain_name] = "WORKSTATION"
        target_info[AvId.dns_computer_name] = to_text(socket.getfqdn())
        target_info[AvId.timestamp] = FileTime.now()

        challenge = Challenge(flags, server_challenge, target_name=target_name, target_info=target_info)

        self._temp_msg = {
            'negotiate': negotiate,
            'challenge': challenge,
        }

        return challenge.pack()

    def _step_accept_authenticate(self, token: bytes) -> None:
        """ Process the Authenticate message from the initiator. """
        challenge = self._temp_msg['challenge']
        server_challenge = challenge.server_challenge
        auth = Authenticate.unpack(token)

        # TODO: Add anonymous user support.
        if not auth.user_name or (not auth.nt_challenge_response and (not auth.lm_challenge_response or
                                                                      auth.lm_challenge_response == b"\x00")):
            raise OperationNotAvailableError(context_msg="Anonymous user authentication not implemented")

        self._credential = _NTLMCredential(domain=auth.domain_name, username=auth.user_name)
        expected_mic = None

        if auth.nt_challenge_response and len(auth.nt_challenge_response) > 24:
            nt_hash = ntowfv2(self._credential.username, self._credential.nt_hash, self._credential.domain)

            nt_challenge = NTClientChallengeV2.unpack(auth.nt_challenge_response[16:])
            time = nt_challenge.time_stamp
            client_challenge = nt_challenge.challenge_from_client
            target_info = nt_challenge.av_pairs

            expected_nt, expected_lm, key_exchange_key = compute_response_v2(
                nt_hash, server_challenge, client_challenge, time, target_info)

            if self.channel_bindings:
                if AvId.channel_bindings not in target_info:
                    raise BadBindingsError(context_msg="Acceptor bindings specified but not present in initiator "
                                                       "response")

                expected_bindings = target_info[AvId.channel_bindings]
                actual_bindings = md5(self.channel_bindings.pack())
                if expected_bindings not in [actual_bindings, b"\x00" * 16]:
                    raise BadBindingsError(context_msg="Acceptor bindings do not match initiator bindings")

            if target_info.get(AvId.flags, 0) & AvFlags.mic:
                expected_mic = auth.mic

        else:
            if not self._nt_v1:
                raise InvalidTokenError(context_msg="Acceptor settings are set to reject NTv1 responses")

            elif not auth.nt_challenge_response and not self._lm:
                raise InvalidTokenError(context_msg="Acceptor settings are set to reject LM responses")

            client_challenge = None
            if auth.flags & NegotiateFlags.extended_session_security:
                client_challenge = auth.lm_challenge_response[:8]

            expected_nt, expected_lm, key_exchange_key = compute_response_v1(
                auth.flags, self._credential.nt_hash, self._credential.lm_hash, server_challenge, client_challenge,
                no_lm_response=not self._lm)

        auth_success = False

        if auth.nt_challenge_response:
            auth_success = auth.nt_challenge_response == expected_nt

        elif auth.lm_challenge_response:
            auth_success = auth.lm_challenge_response == expected_lm

        if not auth_success:
            raise InvalidTokenError(context_msg="Invalid NTLM response from initiator")

        if auth.flags & NegotiateFlags.key_exch and \
                (auth.flags & NegotiateFlags.sign or auth.flags & NegotiateFlags.seal):
            self._session_key = rc4k(key_exchange_key, auth.encrypted_random_session_key)

        else:
            self._session_key = key_exchange_key

        if expected_mic:
            auth.mic = b"\x00" * 16
            actual_mic = self._calculate_mic(self._temp_msg['negotiate'].pack(), challenge.pack(), auth.pack())

            if actual_mic != expected_mic:
                raise InvalidTokenError(context_msg="Invalid MIC in NTLM authentication message")

        self._context_attr = auth.flags
        self._complete = True

    def wrap(self, data: bytes, encrypt: bool = True, qop: typing.Optional[int] = None) -> WrapResult:
        if qop:
            raise UnsupportedQop(context_msg="Unsupported QoP value %s specified for NTLM" % qop)

        if self.context_attr & ContextReq.integrity == 0 and self.context_attr & ContextReq.confidentiality == 0:
            raise OperationNotAvailableError(context_msg="NTLM wrap without integrity or confidentiality")

        msg, signature = seal(self._context_attr, self._handle_out, self._sign_key_out, self._seq_num_out,
                              data)

        return WrapResult(data=signature + msg, encrypted=True)

    def wrap_iov(
        self,
        iov: typing.List[IOVBuffer],
        encrypt: bool = True,
        qop: typing.Optional[int] = None,
    ) -> IOVWrapResult:
        # While this technically works on SSPI by passing multiple data buffers we can achieve the same thing with
        # wrap. Because this context proxy is meant to replicate gss-ntlmssp which doesn't support IOV in NTLM we just
        # fail here.
        raise OperationNotAvailableError(context_msg="NTLM does not offer IOV wrapping")

    def wrap_winrm(self, data: bytes) -> WinRMWrapResult:
        enc_data = self.wrap(data).data
        return WinRMWrapResult(header=enc_data[:16], data=enc_data[16:], padding_length=0)

    def unwrap(self, data: bytes) -> UnwrapResult:
        signature = data[:16]
        msg = self._handle_in.update(data[16:])
        self.verify(msg, signature)

        return UnwrapResult(data=msg, encrypted=True, qop=0)

    def unwrap_iov(self, iov: typing.List[IOVBuffer]) -> IOVUnwrapResult:
        raise OperationNotAvailableError(context_msg="NTLM does not offer IOV wrapping")

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes:
        msg = self._handle_in.update(data)
        self.verify(msg, header)

        return msg

    def sign(self, data: bytes, qop: typing.Optional[int] = None) -> bytes:
        if qop:
            raise UnsupportedQop(context_msg="Unsupported QoP value %s specified for NTLM" % qop)

        return sign(self._context_attr, self._handle_out, self._sign_key_out, self._seq_num_out, data)

    def verify(self, data: bytes, mic: bytes) -> int:
        expected_sig = sign(self._context_attr, self._handle_in, self._sign_key_in, self._seq_num_in, data)

        if expected_sig != mic:
            raise BadMICError(context_msg="Invalid Message integrity Check (MIC) detected")

        return 0

    @property
    def _context_attr_map(self) -> typing.List[typing.Tuple[ContextReq, int]]:
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a4a41f0d-ca27-44bf-ad1d-6f8c3a3796f2
        return [
            (ContextReq.replay_detect, NegotiateFlags.sign),
            (ContextReq.sequence_detect, NegotiateFlags.sign),
            (ContextReq.confidentiality, NegotiateFlags.seal),
            (ContextReq.integrity, NegotiateFlags.sign),
        ]

    @property
    def _requires_mech_list_mic(self) -> bool:
        # If called before the Authenticate message has been created it force the MIC to be present on the message.
        # When called after the Auth message it will return whether the MIC was generated or not.
        if not self._complete:
            self._mic_required = True
            return False

        return self._mic_required

    @property
    def _seq_num_in(self) -> int:
        if self._context_attr & NegotiateFlags.extended_session_security:
            num = self.__seq_num_in
            self.__seq_num_in += 1

        else:
            num = self.__seq_num_out
            self.__seq_num_out += 1

        return num

    @property
    def _seq_num_out(self) -> int:
        num = self.__seq_num_out
        self.__seq_num_out += 1
        return num

    def _calculate_mic(
        self,
        negotiate: bytes,
        challenge: bytes,
        authenticate: bytes,
    ) -> bytes:
        """ Calculates the MIC value for the negotiated context. """
        return hmac_md5(self._session_key, negotiate + challenge + authenticate)

    def _compute_response(
        self,
        challenge: Challenge,
        credential: _NTLMCredential,
    ) -> typing.Tuple[bytes, bytes, bytes]:
        """ Compute the NT and LM responses and the key exchange key. """
        client_challenge = os.urandom(8)

        if self._nt_v2:
            target_info = challenge.target_info.copy() if challenge.target_info else TargetInfo()

            if AvId.timestamp in target_info:
                time = target_info[AvId.timestamp]
                self._mic_required = True

            else:
                time = FileTime.now()

            # The docs seem to indicate that a 0'd bindings hash means to ignore it but that does not seem to be the
            # case. Instead only add the bindings if they have been specified by the caller.
            if self.channel_bindings:
                target_info[AvId.channel_bindings] = md5(self.channel_bindings.pack())
            target_info[AvId.target_name] = self.spn or ""

            if self._mic_required:
                target_info[AvId.flags] = target_info.get(AvId.flags, AvFlags(0)) | AvFlags.mic

            ntv2_hash = ntowfv2(credential.username, credential.nt_hash, credential.domain)
            nt_challenge, lm_challenge, key_exchange_key = compute_response_v2(
                ntv2_hash, challenge.server_challenge, client_challenge, time, target_info)

            if self._mic_required:
                lm_challenge = b"\x00" * 24

            return nt_challenge, lm_challenge, key_exchange_key

        else:
            return compute_response_v1(challenge.flags, credential.nt_hash, credential.lm_hash,
                                       challenge.server_challenge, client_challenge, no_lm_response=not self._lm)

    def _convert_iov_buffer(self, buffer: IOVBuffer) -> typing.Any:
        pass  # IOV is not used in this NTLM provider like gss-ntlmssp. # pragma: no cover

    def _reset_ntlm_crypto_state(self, outgoing: bool = True) -> None:
        self._handle_out.reset() if outgoing else self._handle_in.reset()
