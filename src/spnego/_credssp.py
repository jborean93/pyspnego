# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import hashlib
import logging
import os
import re
import shutil
import ssl
import struct
import tempfile
import typing

import spnego
from spnego._context import (
    ContextProxy,
    ContextReq,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
    split_username,
)
from spnego._credssp_structures import (
    NegoData,
    TSCredentials,
    TSPasswordCreds,
    TSRequest,
)
from spnego._text import to_text
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import (
    BadBindingsError,
    ErrorCode,
    FeatureMissingError,
    InvalidTokenError,
    NativeError,
    NegotiateOptions,
    OperationNotAvailableError,
    SpnegoError,
)
from spnego.tls import (
    CredSSPTLSContext,
    default_tls_context,
    generate_tls_certificate,
    get_certificate_public_key,
)

log = logging.getLogger(__name__)

# The protocol version understood by the client and server.
_CREDSSP_VERSION = 6
_X509_CERTIFICATE: typing.Optional[typing.Tuple[bytes, bytes, bytes]] = None


def _create_tls_context(
    usage: str,
) -> CredSSPTLSContext:
    log.debug("Creating TLS context")
    ctx = default_tls_context()

    if usage == "accept":
        # Cache the result for future operations
        global _X509_CERTIFICATE
        if not _X509_CERTIFICATE:
            _X509_CERTIFICATE = generate_tls_certificate()

        cert_pem, key_pem, public_key = _X509_CERTIFICATE

        # Can't use tempfile.NamedTemporaryFile() as load_cert_chain() opens the file on another handle which fails
        # on Windows as the tempfile requires DELETE share access for that to work.
        temp_dir = tempfile.mkdtemp()
        try:
            cert_path = os.path.join(temp_dir, 'ca.pem')
            with open(cert_path, mode='wb') as fd:
                fd.write(cert_pem)
                fd.write(key_pem)

            ctx.context.load_cert_chain(cert_path)
            ctx.public_key = public_key

        finally:
            shutil.rmtree(temp_dir)

    return ctx


def _get_pub_key_auth(
    pub_key: bytes,
    usage: str,
    nonce: typing.Optional[bytes] = None,
) -> bytes:
    """Computes the public key authentication value.

    Params:
        pub_key: The public key to transform.
        usage: Either `initiate` or `accept` to denote if the key is for the
            client to server or vice versa.
        nonce: A 32 byte nonce used for CredSSP version 5 or newer.

    Returns:
        bytes: The public key authentication value.
    """
    if nonce:
        direction = b'Client-To-Server' if usage == 'initiate' else b'Server-To-Client'
        hash_input = (b'CredSSP %s Binding Hash\x00' % direction) + nonce + pub_key
        key_auth = hashlib.sha256(hash_input).digest()

    elif usage == 'accept':
        first_byte = struct.unpack("B", pub_key[0:1])[0]
        key_auth = struct.pack("B", first_byte + 1) + pub_key[1:]

    else:
        key_auth = pub_key

    return key_auth


def _tls_trailer_length(
    data_length: int,
    protocol: str,
    cipher_suite: str,
) -> int:
    """Gets the length of the TLS trailer.

    WinRM wrapping needs to split the trailer/header with the data but the
    length of the trailer is dependent on the cipher suite that was negotiated.
    On Windows you can get this length by calling `QueryContextAttributes`_
    with the `SecPkgContext_StreamSizes`_ structure. Unfortunately we need to
    work on other platforms so we calculate it manually.

    Params:
        data_length: The length of the TLS data used to calculate the padding
            size.
        protocol: The TLS protocol negotiated between the client and server.
        cipher_suite: The TLS cipher suite negotiated between the client and
            server.

    Returns:
        int: The length of the trailer.

    .. _QueryContextAttributes:
        https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw

    .. _SecPkgContext_StreamSizes:
        https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_streamsizes
    """
    if protocol == 'TLSv1.3':
        # The 2 cipher suites that MS supports for TLS 1.3 (TLS_AES_*_GCM_SHA*) have a fixed length of 17. This may
        # change in the future but it works for now.
        trailer_length = 17

    elif re.match(r'^.*[-_]GCM[-_][\w\d]*$', cipher_suite):
        # GCM has a fixed length of 16 bytes
        trailer_length = 16

    else:
        # For other cipher suites, trailer size == len(hmac) + len(padding) the padding is the length required by the
        # chosen block cipher.
        hash_algorithm = cipher_suite.split('-')[-1]

        # While there are other algorithms, SChannel doesn't support them as of yet so we just keep to this list.
        hash_length = {
            'MD5': 16,
            'SHA': 20,
            'SHA256': 32,
            'SHA384': 48
        }.get(hash_algorithm, 0)

        pre_pad_length = data_length + hash_length
        if "RC4" in cipher_suite:
            # RC4 is a stream cipher so no padding would be added.
            padding_length = 0

        elif "DES" in cipher_suite or "3DES" in cipher_suite:
            # 3DES is a 64 bit block cipher.
            padding_length = 8 - (pre_pad_length % 8)

        else:
            # AES is a 128 bit block cipher.
            padding_length = 16 - (pre_pad_length % 16)

        trailer_length = (pre_pad_length + padding_length) - data_length

    return trailer_length


def _wrap_ssl_error(context):
    def decorator(func):
        def wrapped(*args, **kwargs):
            try:
                return func(*args, **kwargs)

            except ssl.SSLError as e:
                raise SpnegoError(error_code=ErrorCode.failure, context_msg="%s: %s" % (context, e)) from e

        return wrapped
    return decorator


class CredSSPProxy(ContextProxy):
    """CredSSP proxy class CredSSP authentication.

    This proxy class for CredSSP can be used to exchange CredSSP tokens.
    It uses the NegotiateProxy provider for the underlying authentication but
    exchanges the tokens in the exchange required by CredSSP. The main
    advantage of CredSSP is that it allows you to delegate the user's
    credentials to the server.

    The acceptor logic is mostly done as a proof of concept and for use with
    testing. Use at your own risk.

    Optional kwargs supports by CredSSPProxy:

        credssp_negotiate_context: Use this contest for the underlying
            authentication negotiation. This allows the caller to restrict the
            auth to Kerberos or set any other setting specific to their
            environment:

        credssp_tls_context: Custom :class:`CredSSPTLSContext` to use for the
            CredSSP exchange. See `spnego.tls` for helper methods to generate
            a custom TLS context.
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
        protocol: str = 'credssp',
        options: NegotiateOptions = NegotiateOptions.none,
        **kwargs: typing.Any,
    ) -> None:
        super(CredSSPProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                           protocol, options, False)

        if options & NegotiateOptions.session_key:
            raise FeatureMissingError(NegotiateOptions.session_key)

        self._hostname = hostname
        self._service = service
        self._options = options & ~NegotiateOptions.wrapping_winrm  # WinRM wrapping won't apply for auth context.

        self._auth_context: typing.Optional[ContextProxy] = kwargs.get("credssp_negotiate_context", None)
        self._client_credential = None
        self._complete = False
        self._step_gen = None

        self._tls_context: CredSSPTLSContext
        if "credssp_tls_context" in kwargs:
            self._tls_context = kwargs["credssp_tls_context"]

            if usage == "accept" and not self._tls_context.public_key:
                raise OperationNotAvailableError(context_msg="Provided tls context does not have a public key set")
        else:
            self._tls_context = _create_tls_context(usage)

        self._in_buff = ssl.MemoryBIO()
        self._out_buff = ssl.MemoryBIO()
        self._tls_object = self._tls_context.context.wrap_bio(self._in_buff, self._out_buff,
                                                              server_side=(usage == "accept"))

    @classmethod
    def available_protocols(cls, options=None):
        return ['credssp']

    @classmethod
    def iov_available(cls):
        return False

    @property
    def client_principal(self):
        return self._auth_context.client_principal if self._auth_context else None

    @property
    def client_credential(self):
        return self._client_credential

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return self._auth_context.negotiated_protocol if self._auth_context else None

    @property
    def session_key(self):
        raise OperationNotAvailableError(context_msg='CredSSP does not have a session key to share')

    def step(self, in_token=None):
        log.debug("CredSSP step input: %s", to_text(base64.b64encode(in_token or b"")))

        if not self._step_gen:
            self._step_gen = getattr(self, '_step_%s' % self.usage)(in_token)
            in_token = None

        out_token = None
        try:
            out_token = self._step_gen.send(in_token)
        except StopIteration:
            pass

        log.debug("CredSSP step output: %s", to_text(base64.b64encode(out_token or b"")))
        return out_token

    def _step_initiate(
        self,
        in_token: typing.Optional[bytes],
    ) -> typing.Generator[bytes, bytes, None]:
        """ The initiator authentication steps of CredSSP. """
        yield from self._step_tls(in_token)

        server_certificate = self._tls_object.getpeercert(True)
        public_key = get_certificate_public_key(server_certificate)

        log.debug("Starting CredSSP authentication phase")
        if not self._auth_context:
            self._auth_context = spnego.client(self.username, self.password, hostname=self._hostname,
                                               service=self._service, protocol='negotiate', options=self._options)

        round = 0
        out_token = self._auth_context.step()
        while True:
            round += 1
            auth_request = TSRequest(_CREDSSP_VERSION, nego_tokens=NegoData(out_token))

            auth_response = yield from self._yield_ts_request(auth_request, "Authentication %d" % round)
            out_token = self._auth_context.step(auth_response.nego_tokens[0].nego_token)

            # Special edge case, we need to include the final NTLM token in the pubKeyAuth step but the context won't
            # be seen as complete when it's wrapped in SPNEGO. We just check if the known header signature is present.
            if self._auth_context.complete or b"NTLMSSP\x00\x03\x00\x00\x00" in out_token:
                break

        # TODO: Check that version meets minimum requirement
        version = min(auth_response.version, _CREDSSP_VERSION)
        log.debug("Negotiated CredSSP version: %d" % version)

        pub_key_nego_token = NegoData(out_token) if out_token else None
        nonce = os.urandom(32) if version > 4 else None
        pub_value = _get_pub_key_auth(public_key, 'initiate', nonce=nonce)
        pub_key_request = TSRequest(version=_CREDSSP_VERSION, nego_tokens=pub_key_nego_token, client_nonce=nonce,
                                    pub_key_auth=self._auth_context.wrap(pub_value).data)

        pub_key_response = yield from self._yield_ts_request(pub_key_request, "Public key exchange")
        if not pub_key_response.pub_key_auth:
            raise InvalidTokenError(context_msg="Acceptor did not response with pubKeyAuth info.")

        if pub_key_response.nego_tokens:
            # NTLM over SPNEGO auth returned the mechListMIC for us to verify.
            self._auth_context.step(pub_key_response.nego_tokens[0].nego_token)

        response_key = self._auth_context.unwrap(pub_key_response.pub_key_auth).data
        expected_key = _get_pub_key_auth(public_key, 'accept', nonce=nonce)
        if expected_key != response_key:
            raise BadBindingsError(context_msg="Public key verification failed, potential man in the middle attack")

        domain, username = split_username(self.username)
        ts_password = TSPasswordCreds(domain or u'', username, self.password)
        enc_credentials = self._auth_context.wrap(TSCredentials(ts_password).pack()).data

        credential_request = TSRequest(_CREDSSP_VERSION, auth_info=enc_credentials)
        self._complete = True

        yield from self._yield_ts_request(credential_request, "Credential exchange")

    def _step_accept(
        self,
        in_token: typing.Optional[bytes],
    ) -> typing.Generator[bytes, bytes, None]:
        """ The acceptor authentication steps of CredSSP. """
        in_token = yield from self._step_tls(in_token)

        # The version to use as the acceptor should be the smaller of the client and _CREDSSP_VERSION.
        # TODO: Add check that sets minimum client version supported.
        auth_request = TSRequest.unpack(in_token)
        version = min(auth_request.version, _CREDSSP_VERSION)
        log.debug("Negotiated CredSSP version: %d" % version)

        try:
            log.debug("Starting CredSSP authentication phase")
            if not self._auth_context:
                self._auth_context = spnego.server(hostname=self._hostname, service=self._service,
                                                   protocol='negotiate', options=self._options)

            round = 0
            while True:
                round += 1
                nego_out_token = None

                if auth_request.nego_tokens:
                    nego_out_token = self._auth_context.step(auth_request.nego_tokens[0].nego_token)

                if auth_request.pub_key_auth:
                    break

                auth_response = TSRequest(_CREDSSP_VERSION, nego_tokens=NegoData(nego_out_token))
                auth_request = yield from self._yield_ts_request(auth_response, "Authentication %d" % round)

        except SpnegoError as e:
            # Version 2 and 5 don't support the errorCode field and the initiator won't expect a token back.
            log.warning("Received CredSSP error when accepting credentials: %s", e)
            if version in [3, 4] or version >= 6:
                error_token = TSRequest(_CREDSSP_VERSION, error_code=e.nt_status)
                yield from self._yield_ts_request(error_token, "Authentication failure")

            return

        actual_key = self._auth_context.unwrap(auth_request.pub_key_auth).data
        public_key = self._tls_context.public_key
        expected_key = _get_pub_key_auth(public_key, 'initiate', nonce=auth_request.client_nonce)
        if actual_key != expected_key:
            raise BadBindingsError(context_msg="Public key verification failed, potential man in the middle attack")

        nego_token = NegoData(nego_out_token) if nego_out_token else None
        server_key = self._auth_context.wrap(_get_pub_key_auth(public_key, 'accept',
                                                               nonce=auth_request.client_nonce)).data
        pub_key_response = TSRequest(_CREDSSP_VERSION, nego_tokens=nego_token, pub_key_auth=server_key)
        auth_request = yield from self._yield_ts_request(pub_key_response, "Public key exchange")

        if not auth_request.auth_info:
            raise InvalidTokenError(context_msg="No credential received on CredSSP TSRequest from initiator")

        credential = TSCredentials.unpack(self._auth_context.unwrap(auth_request.auth_info).data)
        self._client_credential = credential.credentials
        self._complete = True

    def _step_tls(self, in_token):
        """ The TLS handshake phase of CredSSP. """
        try:
            while True:
                # For an acceptor we start with a token (Client Hello), write this to the memory BIO before processing.
                if in_token:
                    self._in_buff.write(in_token)

                want_read = False
                try:
                    self._tls_object.do_handshake()
                except ssl.SSLWantReadError:
                    # The handshake process requires more data to be exchanged.
                    want_read = True

                # We need to keep on sending the TLS packets until there is nothing left to send.
                out_token = self._out_buff.read()
                if not out_token:
                    break
                in_token = yield out_token

                # TLSv1.3 acceptor has no more work to be done after SSLWantReadError was not raised and it received
                # the last token from the user (first authentication token).
                if not want_read and self.usage == 'accept':
                    out_token = self.unwrap(in_token).data
                    break

        except ssl.SSLError as e:
            raise InvalidTokenError(context_msg="TLS handshake for CredSSP: %s" % e) from e

        cipher, protocol, _ = self._tls_object.cipher()
        log.debug("TLS handshake complete, negotiation details: %s %s", protocol, cipher)
        return out_token

    def _yield_ts_request(
        self,
        ts_request: TSRequest,
        context_msg: str,
    ) -> typing.Generator[bytes, bytes, TSRequest]:
        """ Exchanges a TSRequest between the initiator and acceptor. """
        out_request = ts_request.pack()
        log.debug("CredSSP TSRequest output: %s" % to_text(base64.b64encode(out_request)))
        wrapped_response = yield self.wrap(out_request).data

        in_request = self.unwrap(wrapped_response).data
        log.debug("CredSSP TSRequest input: %s" % to_text(base64.b64encode(in_request)))
        response = TSRequest.unpack(in_request)

        if response.error_code:
            # The error code is an NtStatus value, try to see if it maps to a known error in our exception map.
            base_error = NativeError('Received NTStatus in TSRequest from acceptor', winerror=response.error_code)
            raise SpnegoError(base_error=base_error, context_msg=context_msg)

        return response

    @_wrap_ssl_error("Invalid TLS state when wrapping data")
    def wrap(self, data, encrypt=True, qop=None):
        self._tls_object.write(data)
        return WrapResult(data=self._out_buff.read(), encrypted=True)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise OperationNotAvailableError(context_msg="CredSSP does not offer IOV wrapping")

    def wrap_winrm(self, data):
        enc_data = self.wrap(data).data
        cipher_negotiated, tls_protocol, _ = self._tls_object.cipher()
        trailer_length = _tls_trailer_length(len(data), tls_protocol, cipher_negotiated)

        return WinRMWrapResult(header=enc_data[:trailer_length], data=enc_data[trailer_length:], padding_length=0)

    @_wrap_ssl_error("Invalid TLS state when unwrapping data")
    def unwrap(self, data):
        self._in_buff.write(data)

        chunks = []
        while True:
            try:
                chunks.append(self._tls_object.read())
            except ssl.SSLWantReadError:
                break

        return UnwrapResult(data=b"".join(chunks), encrypted=True, qop=0)

    def unwrap_iov(self, iov):
        raise OperationNotAvailableError(context_msg="CredSSP does not offer IOV wrapping")

    def unwrap_winrm(self, header, data):
        return self.unwrap(header + data).data

    def sign(self, data, qop=None):
        raise OperationNotAvailableError(context_msg="CredSSP does not offer signing")

    def verify(self, data, mic):
        raise OperationNotAvailableError(context_msg="CredSSP does not offer verification")

    @property
    def _context_attr_map(self):
        return []  # Not applicable to CredSSP.

    def _convert_iov_buffer(self, buffer):
        pass  # pragma: no cover
