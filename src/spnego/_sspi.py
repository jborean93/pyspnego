# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import io
import logging
import struct
import typing

from spnego._context import (
    IOV,
    ContextProxy,
    ContextReq,
    IOVUnwrapResult,
    IOVWrapResult,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
    split_username,
    wrap_system_error,
)
from spnego._credential import Credential, CredentialCache, Password, unify_credentials
from spnego._text import to_text
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import InvalidCredentialError, NegotiateOptions, SpnegoError
from spnego.exceptions import WinError as NativeError
from spnego.iov import BufferType, IOVBuffer, IOVResBuffer

log = logging.getLogger(__name__)

HAS_SSPI = True
SSPI_IMP_ERR = None
try:
    from spnego._sspi_raw import ClientContextReq
    from spnego._sspi_raw import Credential as NativeCredential
    from spnego._sspi_raw import (
        CredentialUse,
        SecBuffer,
        SecBufferDesc,
        SecBufferType,
        SecPkgAttr,
        SecPkgInfo,
        SecStatus,
    )
    from spnego._sspi_raw import SecurityContext as SSPISecContext
    from spnego._sspi_raw import (
        ServerContextReq,
        SSPIQoP,
        WinNTAuthIdentity,
        accept_security_context,
        acquire_credentials_handle,
        decrypt_message,
        encrypt_message,
        initialize_security_context,
        make_signature,
        query_context_attributes,
        verify_signature,
    )
    from spnego._sspi_raw.sspi import SecPkgAttrSizes
except ImportError as e:
    SSPI_IMP_ERR = str(e)
    HAS_SSPI = False
    log.debug("SSPI bindings not available, cannot use any SSPIProxy protocols: %s" % e)


def _available_protocols() -> typing.List[str]:
    """Return a list of protocols that SSPIProxy can offer."""
    if HAS_SSPI:
        return ["kerberos", "negotiate", "ntlm"]
    else:
        return []


def _create_iov_result(iov: "SecBufferDesc") -> typing.Tuple[IOVResBuffer, ...]:
    """Converts SSPI IOV buffer to generic IOVBuffer result."""
    buffers = []
    for i in iov:
        buffer_entry = IOVResBuffer(type=BufferType(i.buffer_type), data=i.buffer)
        buffers.append(buffer_entry)

    return tuple(buffers)


def _get_sspi_credential(
    principal: typing.Optional[str],
    protocol: str,
    usage: str,
    credentials: typing.List[Credential],
) -> "NativeCredential":
    """Get the SSPI credential.

    Will get an SSPI credential for the protocol specified. Currently only
    supports Password or CredentialCache credential types.

    Args:
        principal: The principal to use for the AcquireCredentialsHandle call
        protocol: The protocol of the credential.
        usage: Either `initiate` for a client context or `accept` for a server
            context.
        credentials: List of credentials to retrieve from.

    Returns:
        NativeCredential: The handle to the SSPI credential to use.
    """
    credential_kwargs: typing.Dict[str, typing.Any] = {
        "package": protocol,
        "principal": principal,
        "credential_use": CredentialUse.outbound if usage == "initiate" else CredentialUse.inbound,
    }

    for cred in credentials:
        if isinstance(cred, Password):
            domain, username = split_username(cred.username)
            credential_kwargs["auth_data"] = WinNTAuthIdentity(
                to_text(username, nonstring="passthru"),
                to_text(domain, nonstring="passthru"),
                to_text(cred.password, nonstring="passthru"),
            )

            return acquire_credentials_handle(**credential_kwargs)

        elif isinstance(cred, CredentialCache):
            return acquire_credentials_handle(**credential_kwargs)

    raise InvalidCredentialError(context_msg="No applicable credentials available")


class SSPIProxy(ContextProxy):
    """SSPI proxy class for pure SSPI on Windows.

    This proxy class for SSPI exposes this library into a common interface for SPNEGO authentication. This context
    uses compiled C code to interface directly into the SSPI functions on Windows to provide a native SPNEGO
    implementation.
    """

    def __init__(
        self,
        username: typing.Optional[typing.Union[str, Credential, typing.List[Credential]]] = None,
        password: typing.Optional[str] = None,
        hostname: typing.Optional[str] = None,
        service: typing.Optional[str] = None,
        channel_bindings: typing.Optional[GssChannelBindings] = None,
        context_req: ContextReq = ContextReq.default,
        usage: str = "initiate",
        protocol: str = "negotiate",
        options: NegotiateOptions = NegotiateOptions.none,
        **kwargs: typing.Any,
    ) -> None:

        if not HAS_SSPI:
            raise ImportError("SSPIProxy requires the SSPI Cython extension to be compiled: %s" % SSPI_IMP_ERR)

        credentials = unify_credentials(username, password)
        super(SSPIProxy, self).__init__(
            credentials, hostname, service, channel_bindings, context_req, usage, protocol, options
        )

        self._block_size = 0
        self._max_signature = 0
        self._security_trailer = 0

        self._complete = False
        self._context = SSPISecContext()
        self.__seq_num = 0

        try:
            principal = self.spn if usage == "accept" else None
            self._credential = _get_sspi_credential(principal, protocol, usage, credentials)
        except NativeError as win_err:
            raise SpnegoError(base_error=win_err, context_msg="Getting SSPI credential") from win_err

    @classmethod
    def available_protocols(cls, options: typing.Optional[NegotiateOptions] = None) -> typing.List[str]:
        return _available_protocols()

    @property
    def client_principal(self) -> typing.Optional[str]:
        if self.usage == "accept":
            return typing.cast(str, query_context_attributes(self._context, SecPkgAttr.names))
        else:
            return None

    @property
    def complete(self) -> bool:
        return self._complete

    @property
    def negotiated_protocol(self) -> typing.Optional[str]:
        # FIXME: Try and replicate GSSAPI. Will return None for acceptor until the first token is returned. Negotiate
        # for both iniator and acceptor until the context is established.
        package_info = typing.cast(SecPkgInfo, query_context_attributes(self._context, SecPkgAttr.package_info))
        return package_info.name.lower()

    @property
    @wrap_system_error(NativeError, "Retrieving session key")
    def session_key(self) -> bytes:
        return typing.cast(bytes, query_context_attributes(self._context, SecPkgAttr.session_key))

    @wrap_system_error(NativeError, "Processing security token")
    def step(self, in_token: typing.Optional[bytes] = None) -> typing.Optional[bytes]:
        if not self._is_wrapped:
            log.debug("SSPI step input: %s", base64.b64encode(in_token or b"").decode())

        sec_tokens: typing.List[typing.Tuple[int, bytes]] = []
        if in_token:
            in_token = bytearray(in_token)
            sec_tokens.append((SecBufferType.token, in_token))

        if self.channel_bindings:
            sec_tokens.append((SecBufferType.channel_bindings, self._get_native_bindings()))

        in_buffer: typing.Optional[SecBufferDesc] = None
        if sec_tokens:
            in_buffer = SecBufferDesc(len(sec_tokens))
            for idx, sec_token in enumerate(sec_tokens):
                sec_buffer = in_buffer[idx]
                sec_buffer.buffer_type = sec_token[0]
                sec_buffer.buffer = sec_token[1]

        out_buffer = SecBufferDesc(1)
        out_buffer[0].buffer_type = SecBufferType.token

        if self.usage == "initiate":
            context_req = self._context_req | ClientContextReq.allocate_memory
            res = initialize_security_context(
                self._credential,
                self._context,
                self.spn or "",
                context_req=context_req,
                input_buffer=in_buffer,
                output_buffer=out_buffer,
            )
        else:
            context_req = self._context_req | ServerContextReq.allocate_memory
            res = accept_security_context(
                self._credential,
                self._context,
                in_buffer,
                context_req=context_req,
                output_buffer=out_buffer,
            )

        out_token: typing.Optional[bytes] = None
        try:
            raw_bytes = out_buffer[0].buffer
            out_token = bytes(raw_bytes) if raw_bytes else None
        finally:
            out_buffer[0].free()

        self._context_attr = int(self._context.context_attr)

        if res == SecStatus.SEC_E_OK:
            self._complete = True

            attr_sizes = typing.cast(SecPkgAttrSizes, query_context_attributes(self._context, SecPkgAttr.sizes))
            self._block_size = attr_sizes.block_size
            self._max_signature = attr_sizes.max_signature
            self._security_trailer = attr_sizes.security_trailer

        if not self._is_wrapped:
            log.debug("SSPI step output: %s", base64.b64encode(out_token or b"").decode())

        return out_token

    def wrap(self, data: bytes, encrypt: bool = True, qop: typing.Optional[int] = None) -> WrapResult:
        res = self.wrap_iov([BufferType.header, data, BufferType.padding], encrypt=encrypt, qop=qop)
        return WrapResult(data=b"".join([r.data for r in res.buffers if r.data]), encrypted=res.encrypted)

    @wrap_system_error(NativeError, "Wrapping IOV buffer")
    def wrap_iov(
        self,
        iov: typing.Iterable[IOV],
        encrypt: bool = True,
        qop: typing.Optional[int] = None,
    ) -> IOVWrapResult:
        qop = qop or 0
        if encrypt and qop & SSPIQoP.wrap_no_encrypt:
            raise ValueError("Cannot set qop with SECQOP_WRAP_NO_ENCRYPT and encrypt=True")
        elif not encrypt:
            qop |= SSPIQoP.wrap_no_encrypt

        buffers = self._build_iov_list(iov, self._convert_iov_buffer)
        iov_buffer = SecBufferDesc(len(buffers))
        for idx, buffer in enumerate(buffers):
            sec_buffer = iov_buffer[idx]
            sec_buffer.buffer_type = buffer[0]
            sec_buffer.buffer = buffer[1]

        encrypt_message(self._context, iov_buffer, seq_no=self._seq_num, qop=qop)

        return IOVWrapResult(buffers=_create_iov_result(iov_buffer), encrypted=encrypt)

    def wrap_winrm(self, data: bytes) -> WinRMWrapResult:
        iov = self.wrap_iov([BufferType.header, data]).buffers
        header = iov[0].data or b""
        enc_data = iov[1].data or b""

        return WinRMWrapResult(header=header, data=enc_data, padding_length=0)

    def unwrap(self, data: bytes) -> UnwrapResult:
        res = self.unwrap_iov([(BufferType.stream, data), BufferType.data])

        dec_data = res.buffers[1].data or b""
        return UnwrapResult(data=dec_data, encrypted=res.encrypted, qop=res.qop)

    @wrap_system_error(NativeError, "Unwrapping IOV buffer")
    def unwrap_iov(
        self,
        iov: typing.Iterable[IOV],
    ) -> IOVUnwrapResult:
        buffers = self._build_iov_list(iov, self._convert_iov_buffer)
        iov_buffer = SecBufferDesc(len(buffers))
        for idx, buffer in enumerate(buffers):
            sec_buffer = iov_buffer[idx]
            sec_buffer.buffer_type = buffer[0]
            sec_buffer.buffer = buffer[1]

        qop = decrypt_message(self._context, iov_buffer, seq_no=self._seq_num)
        encrypted = qop & SSPIQoP.wrap_no_encrypt == 0

        return IOVUnwrapResult(buffers=_create_iov_result(iov_buffer), encrypted=encrypted, qop=qop)

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes:
        iov = self.unwrap_iov([(BufferType.header, header), data]).buffers
        return iov[1].data or b""

    @wrap_system_error(NativeError, "Signing message")
    def sign(self, data: bytes, qop: typing.Optional[int] = None) -> bytes:
        data = bytearray(data)
        signature = bytearray(self._max_signature)
        iov = SecBufferDesc(2)
        iov[0].buffer_type = SecBufferType.data
        iov[0].buffer = data
        iov[1].buffer_type = SecBufferType.token
        iov[1].buffer = signature
        make_signature(self._context, qop or 0, iov, self._seq_num)

        return iov[1].buffer or b""

    @wrap_system_error(NativeError, "Verifying message")
    def verify(self, data: bytes, mic: bytes) -> int:
        data = bytearray(data)
        mic = bytearray(mic)
        iov = SecBufferDesc(2)
        iov[0].buffer_type = SecBufferType.data
        iov[0].buffer = data
        iov[1].buffer_type = SecBufferType.token
        iov[1].buffer = mic

        return verify_signature(self._context, iov, self._seq_num)

    @property
    def _context_attr_map(self) -> typing.List[typing.Tuple[ContextReq, int]]:
        # The flags values slightly differ for a initiate and accept context.
        sspi_req = ClientContextReq if self.usage == "initiate" else ServerContextReq

        attr_map = [
            # SSPI does not differ between delegate and delegate_policy, it always respects delegate_policy.
            (ContextReq.delegate, "delegate"),
            (ContextReq.delegate_policy, "delegate"),
            (ContextReq.mutual_auth, "mutual_auth"),
            (ContextReq.replay_detect, "replay_detect"),
            (ContextReq.sequence_detect, "sequence_detect"),
            (ContextReq.confidentiality, "confidentiality"),
            (ContextReq.integrity, "integrity"),
            (ContextReq.identify, "identify"),
        ]
        attrs = []
        for spnego_flag, gssapi_name in attr_map:
            attrs.append((spnego_flag, getattr(sspi_req, gssapi_name)))

        return attrs

    @property
    def _seq_num(self) -> int:
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _convert_iov_buffer(self, buffer: IOVBuffer) -> typing.Tuple[int, bytearray]:
        data = bytearray()

        if isinstance(buffer.data, bytes):
            data = bytearray(buffer.data)
        elif isinstance(buffer.data, int) and not isinstance(buffer.data, bool):
            data = bytearray(buffer.data)
        else:
            auto_alloc_size = {
                BufferType.header: self._security_trailer,
                BufferType.padding: self._block_size,
                BufferType.trailer: self._security_trailer,
            }

            # If alloc wasn't explicitly set, only alloc if the type is a specific auto alloc type.
            alloc = buffer.data
            if alloc is None:
                alloc = buffer.type in auto_alloc_size

            if alloc:
                if buffer.type not in auto_alloc_size:
                    raise ValueError(
                        "Cannot auto allocate buffer of type %s.%s" % (type(buffer.type).__name__, buffer.type.name)
                    )

                data = bytearray(auto_alloc_size[buffer.type])

        return (buffer.type, data)

    def _get_native_bindings(self) -> bytearray:
        """Gets the raw byte value of the SEC_CHANNEL_BINDINGS structure."""
        b_bindings = bytearray()
        b_bindings_data = bytearray()

        def _pack_binding(name: str, b_bindings: bytearray, b_bindings_data: bytearray) -> None:
            if name == "application":
                b_data = getattr(self.channel_bindings, "application_data") or b""

            else:
                b_bindings += struct.pack("<I", getattr(self.channel_bindings, "%s_addrtype" % name))
                b_data = getattr(self.channel_bindings, "%s_address" % name) or b""

            b_bindings += struct.pack("<I", len(b_data))
            b_bindings += struct.pack("I", 32 + len(b_bindings_data))
            b_bindings_data += b_data

        _pack_binding("initiator", b_bindings, b_bindings_data)
        _pack_binding("acceptor", b_bindings, b_bindings_data)
        _pack_binding("application", b_bindings, b_bindings_data)

        return b_bindings + b_bindings_data
