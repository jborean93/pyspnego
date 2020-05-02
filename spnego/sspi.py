# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging

from spnego._context import (
    SecurityContextBase,
    requires_context,
    split_username,
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
    verify_signature,
    WinNTAuthIdentity,
)

from spnego._text import (
    to_text,
)

log = logging.getLogger(__name__)


class _SSPI(SecurityContextBase):

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate', is_client=True):
        super(_SSPI, self).__init__(username, password, hostname, service, channel_bindings, delegate, mutual_auth,
                                    replay_detect, sequence_detect, confidentiality, integrity, protocol, is_client)

        self._attr_sizes = None
        self._completed = False
        self._credential = None
        self._context = SSPISecContext()
        self.__seq_num = 0

    @property
    def complete(self):
        return self._completed

    @property
    @requires_context
    def negotiated_protocol(self):
        package_info = query_context_attributes(self._context, SecPkgAttr.package_info)
        return package_info.name.lower()

    @property
    @requires_context
    def session_key(self):
        return query_context_attributes(self._context, SecPkgAttr.session_key)

    def step(self, in_token=None):
        method_name = 'InitializeSecurityContext()' if self._is_client else 'AcceptSecurityContext()'

        sec_tokens = []
        if in_token:
            log.debug("%s input: %s", method_name, to_text(base64.b64encode(in_token)))
            sec_tokens.append(SecBuffer(SecBufferType.token, in_token))

        if self.channel_bindings:
            sec_tokens.append(SecBuffer(SecBufferType.channel_bindings, self.channel_bindings))

        in_buffer = SecBufferDesc(sec_tokens) if sec_tokens else None
        out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])

        try:
            res = self._step(input_buffer=in_buffer, output_buffer=out_buffer)
        except WindowsError as err:
            res = err.winerror
            rc_name = "Unknown Error"
            for name, value in vars(SecStatus).items():
                if isinstance(value, int) and name.startswith("SEC_") and value == res:
                    rc_name = name
                    break

            raise RuntimeError("%s failed: (%d) %s 0x%s - %s" % (method_name, res, rc_name,
                                                                 format(res & 0xFFFFFFFF, '08X'), err.strerror))

        if res == SecStatus.SEC_E_OK:
            self._completed = True
            self._context_attr = self._context.context_attr
            self._attr_sizes = query_context_attributes(self._context, SecPkgAttr.sizes)

        out_token = out_buffer[0].buffer
        log.debug("%s output: %s", method_name, to_text(base64.b64encode(out_token)))

        return out_token

    def _step(self, input_buffer, output_buffer):
        raise NotImplementedError()

    @requires_context
    def wrap(self, data, confidential=True):
        return b"".join(self.wrap_winrm(data, confidential=confidential))

    @requires_context
    def wrap_iov(self, iov, confidential=True):
        qop = 0 if confidential else 0x80000001  # SECQOP_WRAP_NO_ENCRYPT

        buffer = SecBufferDesc(self._build_iov(iov))
        encrypt_message(self._context, buffer, seq_no=self._seq_num, qop=qop)

        return tuple([b.buffer for b in buffer])

    @requires_context
    def unwrap(self, data):
        iov = [
            (SecBufferType.stream, data),
            SecBufferType.data,
        ]
        return self.unwrap_iov(iov)[1]

    @requires_context
    def unwrap_iov(self, iov):
        buffer = SecBufferDesc(self._build_iov(iov))
        decrypt_message(self._context, buffer, seq_no=self._seq_num)

        return tuple([b.buffer for b in buffer])

    @requires_context
    def sign(self, data):
        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.data, buffer=data),
            SecBuffer(SecBufferType.token, length=self._attr_sizes.max_signature),
        ])

        make_signature(self._context, 0, buffer, self._seq_num)

        return buffer[1].buffer

    @requires_context
    def verify(self, data, signature):
        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.data, buffer=data),
            SecBuffer(SecBufferType.token, buffer=signature),
        ])

        return verify_signature(self._context, buffer, self._seq_num)

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _create_spn(self, service, principal):
        return u'%s/%s' % (service.upper(), principal)

    def _iov_buffer(self, buffer_type, data):
        # TODO: Allow a user to specify their own length.
        buffer_kwargs = {}
        if data:
            buffer_kwargs['buffer'] = data
        else:
            if buffer_type in [SecBufferType.token, SecBufferType.stream_header]:
                buffer_kwargs['length'] = self._attr_sizes.security_trailer
            elif buffer_type == SecBufferType.padding:
                buffer_kwargs['length'] = self._attr_sizes.block_size

        return SecBuffer(buffer_type, **buffer_kwargs)


class SSPIClient(_SSPI):

    _CONTEXT_FLAG_MAP = {
        'delegate': ClientContextReq.confidentiality,
        'mutual_auth': ClientContextReq.mutual_auth,
        'replay_detect': ClientContextReq.replay_detect,
        'sequence_detect': ClientContextReq.sequence_detect,
        'confidentiality': ClientContextReq.confidentiality,
        'integrity': ClientContextReq.integrity,
    }

    def __init__(self, username, password, hostname, service='HOST', channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate'):
        super(SSPIClient, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                         mutual_auth, replay_detect, sequence_detect, confidentiality, integrity,
                                         protocol, True)

        domain, username = split_username(self.username)
        auth_data = None
        if username:
            auth_data = WinNTAuthIdentity(to_text(username, nonstring='passthru'),
                                          to_text(domain, nonstring='passthru'),
                                          to_text(password, nonstring='passthru'))

        self._credential = acquire_credentials_handle(None, to_text(protocol, nonstring='passthru'),
                                                      auth_data=auth_data, credential_use=CredentialUse.outbound)

    def _step(self, input_buffer, output_buffer):
        return initialize_security_context(self._credential, self._context, self._spn,
                                           context_req=self._context_req, input_buffer=input_buffer,
                                           output_buffer=output_buffer)


class SSPIServer(_SSPI):

    _CONTEXT_FLAG_MAP = {
        'delegate': ServerContextReq.confidentiality,
        'mutual_auth': ServerContextReq.mutual_auth,
        'replay_detect': ServerContextReq.replay_detect,
        'sequence_detect': ServerContextReq.sequence_detect,
        'confidentiality': ServerContextReq.confidentiality,
        'integrity': ServerContextReq.integrity,
    }

    def __init__(self, hostname, service='HOST', channel_bindings=None, delegate=False, mutual_auth=True,
                 replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True, protocol='negotiate'):
        super(SSPIServer, self).__init__(None, None, hostname, service, channel_bindings, delegate, mutual_auth,
                                         replay_detect, sequence_detect, confidentiality, integrity, protocol, False)

        self._credential = acquire_credentials_handle(self._spn, to_text(protocol, nonstring='passthru'),
                                                      credential_use=CredentialUse.inbound)

    def _step(self, input_buffer, output_buffer):
        return accept_security_context(self._credential, self._context, input_buffer, context_req=self._context_req,
                                       output_buffer=output_buffer)
