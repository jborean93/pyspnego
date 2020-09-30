# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import io
import logging
import struct
import sys

from spnego._compat import (
    List,
    Tuple,

    reraise,
)

from spnego._context import (
    ContextProxy,
    ContextReq,
    IOVWrapResult,
    IOVUnwrapResult,
    split_username,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
    wrap_system_error,
)

from spnego.iov import (
    BufferType,
    IOVBuffer,
)

from spnego._text import (
    text_type,
    to_native,
    to_text,
)

from spnego.exceptions import (
    SpnegoError,
    WinError as NativeError,
)

log = logging.getLogger(__name__)

HAS_SSPI = True
SSPI_IMP_ERR = None
try:
    from spnego._sspi_raw import (
        accept_security_context,
        acquire_credentials_handle,
        ClientContextReq,
        CredentialUse,
        decrypt_message,
        encrypt_message,
        initialize_security_context,
        make_signature,
        query_context_attributes,
        SecBuffer,
        SecBufferDesc,
        SecBufferType,
        SecPkgAttr,
        SecStatus,
        SecurityContext as SSPISecContext,
        ServerContextReq,
        SSPIQoP,
        verify_signature,
        WinNTAuthIdentity,
    )
except ImportError:
    SSPI_IMP_ERR = sys.exc_info()
    HAS_SSPI = False
    log.debug("SSPI bindings not available, cannot use any SSPIProxy protocols: %s" % str(SSPI_IMP_ERR[1]))


def _available_protocols():  # type: () -> List[text_type, ...]
    """ Return a list of protocols that SSPIProxy can offer. """
    if HAS_SSPI:
        return ['kerberos', 'negotiate', 'ntlm']
    else:
        return []


def _create_iov_result(iov):  # type: (SecBufferDesc) -> Tuple[IOVBuffer, ...]
    """ Converts SSPI IOV buffer to generic IOVBuffer result. """
    buffers = []
    for i in iov:
        buffer_entry = IOVBuffer(type=BufferType(i.buffer_type), data=i.buffer)
        buffers.append(buffer_entry)

    return tuple(buffers)


class SSPIProxy(ContextProxy):
    """SSPI proxy class for pure SSPI on Windows.

    This proxy class for SSPI exposes this library into a common interface for SPNEGO authentication. This context
    uses compiled C code to interface directly into the SSPI functions on Windows to provide a native SPNEGO
    implementation.
    """

    def __init__(self, username=None, password=None, hostname=None, service=None, channel_bindings=None,
                 context_req=ContextReq.default, usage='initiate', protocol='negotiate', options=0):

        if not HAS_SSPI:
            reraise(ImportError("SSPIProxy requires the SSPI Cython extension to be compiled"), SSPI_IMP_ERR)

        super(SSPIProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, options, False)

        self._attr_sizes = None
        self._complete = False
        self._credential = None
        self._context = SSPISecContext()
        self.__seq_num = 0

        credential_kwargs = {
            'package': to_text(protocol),
        }

        if usage == 'initiate':
            # TODO: It seems like the SPN is just an empty string for anon auth.
            credential_kwargs['principal'] = None
            credential_kwargs['credential_use'] = CredentialUse.outbound

            if self.username:
                domain, username = split_username(self.username)
                credential_kwargs['auth_data'] = WinNTAuthIdentity(
                    to_text(username, nonstring='passthru'),
                    to_text(domain, nonstring='passthru'),
                    to_text(password, nonstring='passthru'))

        else:
            credential_kwargs['principal'] = self.spn
            credential_kwargs['credential_use'] = CredentialUse.inbound

        try:
            self._credential = acquire_credentials_handle(**credential_kwargs)
        except NativeError as win_err:
            reraise(SpnegoError(base_error=win_err, context_msg="Getting SSPI credential"))

    @classmethod
    def available_protocols(cls, options=None):
        return _available_protocols()

    @property
    def client_principal(self):
        if self.usage == 'accept':
            return query_context_attributes(self._context, SecPkgAttr.names)

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        # FIXME: Try and replicate GSSAPI. Will return None for acceptor until the first token is returned. Negotiate
        # for both iniator and acceptor until the context is established.
        package_info = query_context_attributes(self._context, SecPkgAttr.package_info)
        return to_native(package_info.name).lower()

    @property
    @wrap_system_error(NativeError, "Retrieving session key")
    def session_key(self):
        return query_context_attributes(self._context, SecPkgAttr.session_key)

    @wrap_system_error(NativeError, "Processing security token")
    def step(self, in_token=None):
        log.debug("SSPI step input: %s", to_text(base64.b64encode(in_token or b"")))

        sec_tokens = []
        if in_token:
            sec_tokens.append(SecBuffer(SecBufferType.token, in_token))

        if self.channel_bindings:
            sec_tokens.append(SecBuffer(SecBufferType.channel_bindings, self._get_native_bindings()))

        in_buffer = SecBufferDesc(sec_tokens) if sec_tokens else None
        out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])

        if self.usage == 'initiate':
            res = initialize_security_context(self._credential, self._context, self.spn,
                                              context_req=self._context_req, input_buffer=in_buffer,
                                              output_buffer=out_buffer)
        else:
            res = accept_security_context(self._credential, self._context, in_buffer,
                                          context_req=self._context_req, output_buffer=out_buffer)

        self._context_attr = int(self._context.context_attr)

        if res == SecStatus.SEC_E_OK:
            self._complete = True
            self._attr_sizes = query_context_attributes(self._context, SecPkgAttr.sizes)

        # TODO: Determine if this returns None or an empty byte string.
        out_token = out_buffer[0].buffer

        log.debug("SSPI step output: %s", to_text(base64.b64encode(out_token or b"")))

        return out_token

    def wrap(self, data, encrypt=True, qop=None):
        res = self.wrap_iov([BufferType.header, data, BufferType.padding], encrypt=encrypt, qop=qop)
        return WrapResult(data=b"".join([r.data for r in res.buffers if r.data]), encrypted=res.encrypted)

    @wrap_system_error(NativeError, "Wrapping IOV buffer")
    def wrap_iov(self, iov, encrypt=True, qop=None):
        qop = qop or 0
        if encrypt and qop & SSPIQoP.wrap_no_encrypt:
            raise ValueError("Cannot set qop with SECQOP_WRAP_NO_ENCRYPT and encrypt=True")
        elif not encrypt:
            qop |= SSPIQoP.wrap_no_encrypt

        iov_buffer = SecBufferDesc(self._build_iov_list(iov))
        encrypt_message(self._context, iov_buffer, seq_no=self._seq_num, qop=qop)

        return IOVWrapResult(buffers=_create_iov_result(iov_buffer), encrypted=encrypt)

    def wrap_winrm(self, data):
        iov = self.wrap_iov([BufferType.header, data]).buffers
        enc_data = iov[1].data

        return WinRMWrapResult(header=iov[0].data, data=enc_data, padding_length=0)

    def unwrap(self, data):
        res = self.unwrap_iov([(BufferType.stream, data), BufferType.data])
        return UnwrapResult(data=res.buffers[1].data, encrypted=res.encrypted, qop=res.qop)

    @wrap_system_error(NativeError, "Unwrapping IOV buffer")
    def unwrap_iov(self, iov):
        iov_buffer = SecBufferDesc(self._build_iov_list(iov))
        qop = decrypt_message(self._context, iov_buffer, seq_no=self._seq_num)
        encrypted = qop & SSPIQoP.wrap_no_encrypt == 0

        return IOVUnwrapResult(buffers=_create_iov_result(iov_buffer), encrypted=encrypted, qop=qop)

    def unwrap_winrm(self, header, data):
        iov = self.unwrap_iov([(BufferType.header, header), data]).buffers
        return iov[1].data

    @wrap_system_error(NativeError, "Signing message")
    def sign(self, data, qop=None):
        iov = SecBufferDesc(self._build_iov_list([
            data,
            (BufferType.header, self._attr_sizes.max_signature)
        ]))
        make_signature(self._context, qop or 0, iov, self._seq_num)

        return iov[1].buffer

    @wrap_system_error(NativeError, "Verifying message")
    def verify(self, data, signature):
        iov = SecBufferDesc(self._build_iov_list([
            data,
            (BufferType.header, signature),
        ]))

        return verify_signature(self._context, iov, self._seq_num)

    @property
    def _context_attr_map(self):
        # The flags values slightly differ for a initiate and accept context.
        sspi_req = ClientContextReq if self.usage == 'initiate' else ServerContextReq

        attr_map = [
            # SSPI does not differ between delegate and delegate_policy, it always respects delegate_policy.
            (ContextReq.delegate, 'delegate'),
            (ContextReq.delegate_policy, 'delegate'),
            (ContextReq.mutual_auth, 'mutual_auth'),
            (ContextReq.replay_detect, 'replay_detect'),
            (ContextReq.sequence_detect, 'sequence_detect'),
            (ContextReq.confidentiality, 'confidentiality'),
            (ContextReq.integrity, 'integrity'),
            (ContextReq.identify, 'identify'),
        ]
        attrs = []
        for spnego_flag, gssapi_name in attr_map:
            attrs.append((spnego_flag, getattr(sspi_req, gssapi_name)))

        return attrs

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _convert_iov_buffer(self, iov_buffer):  # type: (IOVBuffer) -> SecBuffer
        kwargs = {}

        if isinstance(iov_buffer.data, bytes):
            kwargs['buffer'] = iov_buffer.data
        elif isinstance(iov_buffer.data, int) and not isinstance(iov_buffer.data, bool):
            kwargs['length'] = iov_buffer.data
        else:
            auto_alloc_size = {
                BufferType.header: self._attr_sizes.security_trailer,
                BufferType.padding: self._attr_sizes.block_size,
                BufferType.trailer: self._attr_sizes.security_trailer,
            }

            # If alloc wasn't explicitly set, only alloc if the type is a specific auto alloc type.
            alloc = iov_buffer.data
            if alloc is None:
                alloc = iov_buffer.type in auto_alloc_size

            if alloc:
                if iov_buffer.type not in auto_alloc_size:
                    raise ValueError("Cannot auto allocate buffer of type %s" % iov_buffer.type)

                kwargs['length'] = auto_alloc_size[iov_buffer.type]

        return SecBuffer(iov_buffer.type, **kwargs)

    def _get_native_bindings(self):
        """ Gets the raw byte value of the SEC_CHANNEL_BINDINGS structure. """
        b_bindings = io.BytesIO()
        b_bindings_data = io.BytesIO()

        def _pack_binding(name):
            if name == 'application':
                b_data = self.channel_bindings.application_data or b""

            else:
                b_bindings.write(struct.pack("<I", getattr(self.channel_bindings, '%s_addrtype' % name)))
                b_data = getattr(self.channel_bindings, '%s_address' % name) or b""

            b_bindings.write(struct.pack("<I", len(b_data)))
            b_bindings.write(struct.pack("I", 32 + b_bindings_data.tell()))
            b_bindings_data.write(b_data)

        _pack_binding('initiator')
        _pack_binding('acceptor')
        _pack_binding('application')

        return b_bindings.getvalue() + b_bindings_data.getvalue()
