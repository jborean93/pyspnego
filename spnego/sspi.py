# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
from typing import Tuple

from spnego._context import (
    ContextProxy,
    ContextReq,
    DEFAULT_REQ,
    IOVWrapResult,
    IOVUnwrapResult,
    split_username,
    UnwrapResult,
    WrapResult,
)

from spnego.iov import (
    BufferType,
    IOVBuffer,
)

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

from spnego._text import (
    to_text,
)


log = logging.getLogger(__name__)


class SSPIProxy(ContextProxy):
    """SSPI proxy class for pure SSPI on Windows.

    This proxy class for SSPI exposes this library into a common interface for SPNEGO authentication. This context
    uses compiled C code to interface directly into the SSPI functions on Windows to provide a native SPNEGO
    implementation.

    Args:
    """

    def __init__(self, username=None, password=None, hostname='unspecified', service='host', channel_bindings=None,
                 context_req=DEFAULT_REQ, usage='initiate', protocol='negotiate'):
        super(SSPIProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                        protocol, False)

        self._attr_sizes = None
        self._complete = False
        self._credential = None
        self._context = SSPISecContext()
        self.__seq_num = 0

        protocol = to_text(protocol)
        if usage == 'initiate':
            domain, username = split_username(self.username)
            auth_data = None
            if username:
                auth_data = WinNTAuthIdentity(to_text(username, nonstring='passthru'),
                                              to_text(domain, nonstring='passthru'),
                                              to_text(password, nonstring='passthru'))

            # TODO: It seems like the SPN is just an empty string for anon auth.
            self._credential = acquire_credentials_handle(None, protocol, auth_data=auth_data,
                                                          credential_use=CredentialUse.outbound)
        else:
            self._credential = acquire_credentials_handle(self.spn, protocol, credential_use=CredentialUse.inbound)

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        package_info = query_context_attributes(self._context, SecPkgAttr.package_info)
        return to_text(package_info.name).lower()

    @property
    def session_key(self):
        return query_context_attributes(self._context, SecPkgAttr.session_key)

    def step(self, in_token=None):
        sec_tokens = []
        if in_token:
            sec_tokens.append(SecBuffer(SecBufferType.token, in_token))

        if self._channel_bindings:
            sec_tokens.append(SecBuffer(SecBufferType.channel_bindings, self._channel_bindings))

        in_buffer = SecBufferDesc(sec_tokens) if sec_tokens else None
        out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])

        try:
            if self.usage == 'initiate':
                res = initialize_security_context(self._credential, self._context, self.spn,
                                                  context_req=self._context_req, input_buffer=in_buffer,
                                                  output_buffer=out_buffer)
            else:
                res = accept_security_context(self._credential, self._context, in_buffer,
                                              context_req=self._context_req, output_buffer=out_buffer)
        except WindowsError as err:
            res = err.winerror
            rc_name = "Unknown Error"
            for name, value in vars(SecStatus).items():
                if isinstance(value, int) and name.startswith("SEC_") and value == res:
                    rc_name = name
                    break

            raise RuntimeError("SSPI step failed: (%d) %s 0x%s - %s" % (res, rc_name, format(res & 0xFFFFFFFF, '08X'),
                                                                        err.strerror))

        self._context_attr = int(self._context.context_attr)

        if res == SecStatus.SEC_E_OK:
            self._complete = True
            self._attr_sizes = query_context_attributes(self._context, SecPkgAttr.sizes)

        # TODO: Determine if this returns None or an empty byte string.
        return out_buffer[0].buffer

    def wrap(self, data, encrypt=True, qop=None):
        res = self.wrap_iov([BufferType.header, data, BufferType.padding], encrypt=encrypt, qop=qop)
        return WrapResult(data=b"".join([r.data for r in res.buffers]), encrypted=res.encrypted)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        if not self.integrity:
            raise NotImplementedError("No integrity")

        if encrypt and not self.confidentiality:
            raise NotImplementedError("No confidentiality")

        qop = qop or 0
        if encrypt and qop & SSPIQoP.wrap_no_encrypt:
            raise ValueError("Cannot set qop with SECQOP_WRAP_NO_ENCRYPT and encrypt=True")
        elif not encrypt:
            qop |= SSPIQoP.wrap_no_encrypt

        buffer = SecBufferDesc(self._build_iov_list(iov))
        encrypt_message(self._context, buffer, seq_no=self._seq_num, qop=qop)

        return IOVWrapResult(buffers=self._create_iov_result(buffer), encrypted=encrypt)

    def unwrap(self, data):
        res = self.unwrap_iov([(BufferType.stream, data), BufferType.data])
        return UnwrapResult(data=res.buffers[1].data, encrypted=res.encrypted, qop=res.qop)

    def unwrap_iov(self, iov):
        buffer = SecBufferDesc(self._build_iov_list(iov))
        qop = decrypt_message(self._context, buffer, seq_no=self._seq_num)
        encrypted = qop & SSPIQoP.wrap_no_encrypt == 0

        return IOVUnwrapResult(buffers=self._create_iov_result(buffer), encrypted=encrypted, qop=qop)

    def sign(self, data, qop=None):
        if not self.integrity:
            raise NotImplementedError("No integrity")

        iov = SecBufferDesc(self._build_iov_list([
            data,
            (BufferType.header, self._attr_sizes.max_signature)
        ]))
        make_signature(self._context, qop, iov, self._seq_num)

        return iov[1].buffer

    def verify(self, data, signature):
        iov = SecBufferDesc(self._build_iov_list([
            data,
            (BufferType.header, signature),
        ]))

        return verify_signature(self._context, iov, self._seq_num)

    @property
    def _context_attr_map(self):
        # The flags values slightly differ for a initiate and accept context.
        if self.usage == 'initiate':
            return [
                (ContextReq.delegate, ClientContextReq.delegate),
                (ContextReq.delegate_policy, ClientContextReq.delegate),
                (ContextReq.mutual_auth, ClientContextReq.mutual_auth),
                (ContextReq.replay_detect, ClientContextReq.replay_detect),
                (ContextReq.sequence_detect, ClientContextReq.sequence_detect),
                (ContextReq.confidentiality, ClientContextReq.confidentiality),
                (ContextReq.integrity, ClientContextReq.integrity),
                (ContextReq.anonymous, None),
                (ContextReq.identify, ClientContextReq.identify),
            ]
        else:
            return [
                (ContextReq.delegate, ServerContextReq.delegate),
                (ContextReq.delegate_policy, ServerContextReq.delegate),
                (ContextReq.mutual_auth, ServerContextReq.mutual_auth),
                (ContextReq.replay_detect, ServerContextReq.replay_detect),
                (ContextReq.sequence_detect, ServerContextReq.sequence_detect),
                (ContextReq.confidentiality, ServerContextReq.confidentiality),
                (ContextReq.integrity, ServerContextReq.integrity),
                (ContextReq.anonymous, None),
                (ContextReq.identify, ServerContextReq.identify),
            ]

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _convert_iov_buffer(self, buffer):  # type: (IOVBuffer) -> SecBuffer
        kwargs = {}

        if isinstance(buffer.data, bytes):
            kwargs['buffer'] = buffer.data
        elif isinstance(buffer.data, int):
            kwargs['length'] = buffer.data
        else:
            auto_alloc_size = {
                BufferType.header: self._attr_sizes.security_trailer,
                BufferType.padding: self._attr_sizes.block_size,
                BufferType.trailer: self._attr_sizes.security_trailer,
            }

            # If alloc wasn't explicitly set, only alloc if the type is a specific auto alloc type.
            alloc = buffer.data
            if alloc is None:
                alloc = buffer.type in auto_alloc_size

            if alloc:
                if buffer.type not in auto_alloc_size:
                    raise ValueError("Cannot auto allocate buffer of type %s" % buffer.type)

                kwargs['length'] = auto_alloc_size[buffer.type]

        return SecBuffer(buffer.type, **kwargs)

    def _create_iov_result(self, iov):  # type: (SecBufferDesc) -> Tuple[IOVBuffer, ...]
        buffers = []
        for i in iov:
            buffer_entry = IOVBuffer(type=BufferType(i.buffer_type), data=i.buffer)
            buffers.append(buffer_entry)

        return tuple(buffers)

    def _create_spn(self, service, principal):
        return u"%s\\%s" % (service.upper(), principal)

