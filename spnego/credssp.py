# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import collections
import datetime
import hashlib
import logging
import os
import platform
import re
import shutil
import spnego
import ssl
import struct
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from spnego._context import (
    ContextProxy,
    ContextReq,
    split_username,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
)

from spnego._credssp_structures import (
    NegoData,
    TSCredentials,
    TSPasswordCreds,
    TSRequest,
)

from spnego._text import (
    to_text,
)

from spnego.exceptions import (
    BadBindingsError,
    ErrorCode,
    InvalidTokenError,
    FeatureMissingError,
    NativeError,
    NegotiateOptions,
    OperationNotAvailableError,
    SpnegoError,
)

from typing import (
    Generator,
    Optional,
    Tuple,
)

TLSContext = collections.namedtuple('TLSContext', ['context', 'public_key'])
"""A TLS context generated for CredSSP.

Defines the TLS context and public key used in the context for an acceptor.

Attributes:
    context (ssl.SSLContext): The TLS context generated for CredSSP
    public_key (Optional[bytes]): When generating the TLS context for an acceptor this is the public key bytes for the
        generated cert in the TLS context.
"""

# Used by test to test a specific TLS version
_PROTOCOL_TLS = ssl.PROTOCOL_TLS

# The protocol version understood by the client and server.
_CREDSSP_VERSION = 6


log = logging.getLogger(__name__)


def _create_tls_context(usage, options):  # type: (str, NegotiateOptions) -> TLSContext
    """Creates the TLS context.

    Creates the TLS context used to generate the SSL object for CredSSP authentication. By default the TLS context will
    set the minimum protocol to TLSv1.2. Verification is also disabled for both the initiator and acceptor as per the
    `MS-CSSP Events and Sequencing Rules`_ in step 1.

    The following options can be set to control the behaviour of the new TLS context that is created:

    NegotiateOptions.credssp_allow_tlsv1:
        Set the minimum protocol to TLSv1.0 for use when authenticating with a host that does not support TLSv1.2.

    Params:
        usage: Set to `initiate` or `accept` to define whether the context is for the initiator or acceptor.
        options: The context requirements of :class:`NegotiationOptions` that control the TLS context behaviour.

    Returns:
        TLSContext: The TLS context and optional public key for the acceptor context.

    .. _MS-CSSP Events and Sequencing Rules:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c
    """
    log.debug("Creating TLS context")
    ctx = ssl.SSLContext(_PROTOCOL_TLS)

    # Required to interop with SChannel which does not support compression, TLS padding, and empty fragments
    # SSL_OP_NO_COMPRESSION | SSL_OP_TLS_BLOCK_PADDING_BUG | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    ctx.options |= ssl.OP_NO_COMPRESSION | 0x00000200 | 0x00000800

    # The minimum_version field requires OpenSSL 1.1.0g or newer, fallback to the deprecated method of setting the
    # OP_NO_* options.
    use_tls1 = bool(options & NegotiateOptions.credssp_allow_tlsv1)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1 if use_tls1 else ssl.TLSVersion.TLSv1_3
    except (ValueError, AttributeError):
        ctx.options |= ssl.Options.OP_NO_SSLv2 | ssl.Options.OP_NO_SSLv3
        if not use_tls1:
            ctx.options |= ssl.Options.OP_NO_TLSv1 | ssl.Options.OP_NO_TLSv1_1

    public_key = None
    if usage == 'accept':
        cert_pem, key_pem, public_key = _generate_credssp_certificate()

        # Can't use tempfile.NamedTemporaryFile() as load_cert_chain() opens the file on another handle which fails
        # on Windows as the tempfile requires DELETE share access for that to work.
        temp_dir = tempfile.mkdtemp()
        try:
            cert_path = os.path.join(temp_dir, 'ca.pem')
            with open(cert_path, mode='wb') as fd:
                fd.write(cert_pem)
                fd.write(key_pem)

            ctx.load_cert_chain(cert_path)

        finally:
            shutil.rmtree(temp_dir)

    return TLSContext(ctx, public_key)


def _generate_credssp_certificate():  # type: () -> Tuple[bytes, bytes, bytes]
    """Generates X509 cert and key for CredSSP acceptor.

    Generates a random TLS X509 certificate and key that is used by a CredSSP acceptor for authentication. This
    certificate is a barebones certificate that is modelled after the one that the WSMan CredSSP service presents.

    Returns:
        Tuple[bytes, bytes, bytes]: The X509 PEM encoded certificate, PEM encoded key, and DER encoded public key.
    """
    # Cache the result as this can be expensive to create if running multiple acceptors
    try:
        return _generate_credssp_certificate.result
    except AttributeError:
        pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # socket.getfqdn() can block for a few seconds if DNS is not set up properly.
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'CREDSSP-%s' % platform.node())])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())
    public_key = cert.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.PKCS1)

    _generate_credssp_certificate.result = cert_pem, key_pem, public_key
    return _generate_credssp_certificate()


def _get_pub_key_auth(pub_key, usage, nonce=None):  # type: (bytes, str, Optional[bytes]) -> bytes
    """Computes the public key authentication value.

    Params:
        pub_key: The public key to transform.
        usage: Either `initiate` or `accept` to denote if the key is for the client to server or vice versa.
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


def _tls_trailer_length(data_length, protocol, cipher_suite):  # type: (int, str, str) -> int
    """Gets the length of the TLS trailer.

    WinRM wrapping needs to split the trailer/header with the data but the length of the trailer is dependent on the
    cipher suite that was negotiated. On Windows you can get this length by calling `QueryContextAttributes`_ with the
    `SecPkgContext_StreamSizes`_ structure. Unfortunately we need to work on other platforms so we calculate it
    manually.

    Params:
        data_length: The length of the TLS data used to calculate the padding size.
        protocol: The TLS protocol negotiated between the client and server.
        cipher_suite: The TLS cipher suite negotiated between the client and server.

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

    This proxy class for CredSSP can be used to exchange CredSSP tokens. It uses the NegotiateProxy provider for the
    underlying authentication but exchanges the tokens in the exchange required by CredSSP. The main advantage of
    CredSSP is that it allows you to delegate the user's credentials to the server.

    The acceptor logic is mostly done as a proof of concept and for use with testing. Use at your own risk.
    """
    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None,
                 context_req=ContextReq.default, usage='initiate', protocol='credssp', options=0):
        super(CredSSPProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                           protocol, options, False)

        if options & NegotiateOptions.session_key:
            raise FeatureMissingError(NegotiateOptions.session_key)

        self._hostname = hostname
        self._service = service
        self._options = options & ~NegotiateOptions.wrapping_winrm  # WinRM wrapping won't apply for auth context.

        self._auth_context = None
        self._client_credential = None
        self._complete = False
        self._step_gen = None

        self._in_buff = ssl.MemoryBIO()
        self._out_buff = ssl.MemoryBIO()
        ctx, self._public_key = _create_tls_context(usage, options)
        self._tls_context = ctx.wrap_bio(self._in_buff, self._out_buff, server_side=(usage == 'accept'))

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

    def _step_initiate(self, in_token):  # type: (Optional[bytes]) -> Generator[bytes, bytes, None]
        """ The initiator authentication steps of CredSSP. """
        yield from self._step_tls(in_token)

        server_certificate = self._tls_context.getpeercert(True)
        cert = x509.load_der_x509_certificate(server_certificate, default_backend())
        self._public_key = cert.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.PKCS1)

        log.debug("Starting CredSSP authentication phase")
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
        pub_value = _get_pub_key_auth(self._public_key, 'initiate', nonce=nonce)
        pub_key_request = TSRequest(version=_CREDSSP_VERSION, nego_tokens=pub_key_nego_token, client_nonce=nonce,
                                    pub_key_auth=self._auth_context.wrap(pub_value).data)

        pub_key_response = yield from self._yield_ts_request(pub_key_request, "Public key exchange")
        if not pub_key_response.pub_key_auth:
            raise InvalidTokenError(context_msg="Acceptor did not response with pubKeyAuth info.")

        if pub_key_response.nego_tokens:
            # NTLM over SPNEGO auth returned the mechListMIC for us to verify.
            self._auth_context.step(pub_key_response.nego_tokens[0].nego_token)

        response_key = self._auth_context.unwrap(pub_key_response.pub_key_auth).data
        expected_key = _get_pub_key_auth(self._public_key, 'accept', nonce=nonce)
        if expected_key != response_key:
            raise BadBindingsError(context_msg="Public key verification failed, potential man in the middle attack")

        domain, username = split_username(self.username)
        ts_password = TSPasswordCreds(domain or u'', username, self.password)
        enc_credentials = self._auth_context.wrap(TSCredentials(ts_password).pack()).data

        credential_request = TSRequest(_CREDSSP_VERSION, auth_info=enc_credentials)
        self._complete = True

        yield from self._yield_ts_request(credential_request, "Credential exchange")

    def _step_accept(self, in_token):  # type: (Optional[bytes]) -> Generator[bytes, bytes, None]
        """ The acceptor authentication steps of CredSSP. """
        in_token = yield from self._step_tls(in_token)

        # The version to use as the acceptor should be the smaller of the client and _CREDSSP_VERSION.
        # TODO: Add check that sets minimum client version supported.
        auth_request = TSRequest.unpack(in_token)
        version = min(auth_request.version, _CREDSSP_VERSION)
        log.debug("Negotiated CredSSP version: %d" % version)

        try:
            log.debug("Starting CredSSP authentication phase")
            self._auth_context = spnego.server(hostname=self._hostname, service=self._service, protocol='negotiate',
                                               options=self._options)

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
        expected_key = _get_pub_key_auth(self._public_key, 'initiate', nonce=auth_request.client_nonce)
        if actual_key != expected_key:
            raise BadBindingsError(context_msg="Public key verification failed, potential man in the middle attack")

        nego_token = NegoData(nego_out_token) if nego_out_token else None
        server_key = self._auth_context.wrap(_get_pub_key_auth(self._public_key, 'accept',
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
                    self._tls_context.do_handshake()
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

        cipher, protocol, _ = self._tls_context.cipher()
        log.debug("TLS handshake complete, negotiation details: %s %s", protocol, cipher)
        return out_token

    def _yield_ts_request(self, ts_request, context_msg):
        # type: (TSRequest, str) -> Generator[bytes, bytes, TSRequest]
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
        self._tls_context.write(data)
        return WrapResult(data=self._out_buff.read(), encrypted=True)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise OperationNotAvailableError(context_msg="CredSSP does not offer IOV wrapping")

    def wrap_winrm(self, data):
        enc_data = self.wrap(data).data
        cipher_negotiated, tls_protocol, _ = self._tls_context.cipher()
        trailer_length = _tls_trailer_length(len(data), tls_protocol, cipher_negotiated)

        return WinRMWrapResult(header=enc_data[:trailer_length], data=enc_data[trailer_length:], padding_length=0)

    @_wrap_ssl_error("Invalid TLS state when unwrapping data")
    def unwrap(self, data):
        self._in_buff.write(data)

        chunks = []
        while True:
            try:
                chunks.append(self._tls_context.read())
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
