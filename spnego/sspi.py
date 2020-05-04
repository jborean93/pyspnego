# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

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
                                        protocol)

        self._attr_sizes = None
        self._complete = False
        self._credential = None
        self._context = SSPISecContext()
        self.__seq_num = 0

        protocol = to_text(protocol)
        if usage == 'initiate':
            self._context_req_map = [
                (ContextReq.delegate, ClientContextReq.confidentiality),
                (ContextReq.delegate_policy, ClientContextReq.confidentiality),
                (ContextReq.mutual_auth, ClientContextReq.mutual_auth),
                (ContextReq.replay_detect, ClientContextReq.replay_detect),
                (ContextReq.sequence_detect, ClientContextReq.sequence_detect),
                (ContextReq.confidentiality, ClientContextReq.confidentiality),
                (ContextReq.integrity, ClientContextReq.integrity),
            ]

            domain, username = split_username(self.username)
            auth_data = None
            if username:
                auth_data = WinNTAuthIdentity(to_text(username, nonstring='passthru'),
                                              to_text(domain, nonstring='passthru'),
                                              to_text(password, nonstring='passthru'))

            self._credential = acquire_credentials_handle(None, protocol, auth_data=auth_data,
                                                          credential_use=CredentialUse.outbound)
        else:
            self._context_req_map = [
                (ContextReq.delegate, ServerContextReq.confidentiality),
                (ContextReq.delegate_policy, ServerContextReq.confidentiality),
                (ContextReq.mutual_auth, ServerContextReq.mutual_auth),
                (ContextReq.replay_detect, ServerContextReq.replay_detect),
                (ContextReq.sequence_detect, ServerContextReq.sequence_detect),
                (ContextReq.confidentiality, ServerContextReq.confidentiality),
                (ContextReq.integrity, ServerContextReq.integrity),
            ]
            self._credential = acquire_credentials_handle(self.spn, protocol, credential_use=CredentialUse.inbound)

        self._sspi_context_req = 0
        for spnego_flag, sspi_flag in self._context_req_map:
            if self.context_req & spnego_flag:
                self._sspi_context_req |= sspi_flag

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

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def create_spn(self, service, principal):
        return u"%s\\%s" % (service.upper(), principal)

    def step(self, in_token=None):
        sec_tokens = []
        if in_token:
            sec_tokens.append(SecBuffer(SecBufferType.token, in_token))

        if self.channel_bindings:
            sec_tokens.append(SecBuffer(SecBufferType.channel_bindings, self.channel_bindings))

        in_buffer = SecBufferDesc(sec_tokens) if sec_tokens else None
        out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])

        try:
            if self.usage == 'initiate':
                res = initialize_security_context(self._credential, self._context, self.spn,
                                                  context_req=self._sspi_context_req, input_buffer=in_buffer,
                                                  output_buffer=out_buffer)
            else:
                res = accept_security_context(self._credential, self._context, in_buffer,
                                              context_req=self._sspi_context_req, output_buffer=out_buffer)
        except WindowsError as err:
            res = err.winerror
            rc_name = "Unknown Error"
            for name, value in vars(SecStatus).items():
                if isinstance(value, int) and name.startswith("SEC_") and value == res:
                    rc_name = name
                    break

            raise RuntimeError("SSPI step failed: (%d) %s 0x%s - %s" % (res, rc_name, format(res & 0xFFFFFFFF, '08X'),
                                                                        err.strerror))

        if res == SecStatus.SEC_E_OK:
            self._complete = True
            self._attr_sizes = query_context_attributes(self._context, SecPkgAttr.sizes)

            self.context_attr = ContextReq()
            for spnego_flag, sspi_flag in self._context_req_map:
                if self._context.context_attr & sspi_flag:
                    self.context_attr |= spnego_flag

        # TODO: Determine if this returns None or an empty byte string.
        return out_buffer[0].buffer

    def wrap(self, data, encrypt=True, qop=None):
        iov = SecBufferDesc([
            SecBuffer(SecBufferType.token),
            SecBuffer(SecBufferType.data, buffer=data),
            SecBuffer(SecBufferType.padding),
        ])
        res = self.wrap_iov(iov, encrypt=encrypt, qop=qop)
        return WrapResult(data=b"".join(res.buffers), encrypted=res.encrypted)

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

        buffer = iov
        encrypt_message(self._context, buffer, seq_no=self._seq_num, qop=qop)

        return IOVWrapResult(buffers=tuple([b.buffer for b in buffer]), encrypted=encrypt)

    def unwrap(self, data):
        iov = SecBufferDesc([
            SecBuffer(SecBufferType.stream, buffer=data),
            SecBuffer(SecBufferType.data),
        ])
        res = self.unwrap_iov(iov)
        return UnwrapResult(data=res.buffers[1], encrypted=res.encrypted, qop=res.qop)

    def unwrap_iov(self, iov):
        buffer = iov
        qop = decrypt_message(self._context, buffer, seq_no=self._seq_num)
        encrypted = qop & SSPIQoP.wrap_no_encrypt == 0

        return IOVUnwrapResult(buffers=tuple([b.buffer for b in buffer]), encrypted=encrypted, qop=qop)

    def sign(self, data, qop=None):
        if not self.integrity:
            raise NotImplementedError("No integrity")

        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.data, buffer=data),
            SecBuffer(SecBufferType.token, length=self._attr_sizes.max_signature),
        ])

        make_signature(self._context, qop, buffer, self._seq_num)

        return buffer[1].buffer

    def verify(self, data, signature):
        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.data, buffer=data),
            SecBuffer(SecBufferType.token, buffer=signature),
        ])

        return verify_signature(self._context, buffer, self._seq_num)

    def convert_channel_bindings(self, bindings):
        return bindings.get_data()
