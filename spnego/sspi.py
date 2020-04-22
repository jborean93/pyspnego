# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging

from spnego._context import (
    SecurityContext,
    requires_context,
    split_username,
)

from spnego._sspi_raw import (
    acquire_credentials_handle,
    ClientContextReq,
    decrypt_message,
    encrypt_message,
    initialize_security_context,
    query_context_attributes,
    SecBuffer,
    SecBufferDesc,
    SecBufferType,
    SecPkgAttr,
    SecStatus,
    SecurityContext as SSPISecContext,
    WinNTAuthIdentity,
)

from spnego._text import (
    to_text,
)

log = logging.getLogger(__name__)


class SSPI(SecurityContext):

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=None,
                 confidentiality=True, protocol='negotiate'):
        super(SSPI, self).__init__(username, password, hostname, service, channel_bindings, delegate, confidentiality,
                                   protocol)
        domain, username = split_username(self.username)

        self._target_spn = u'%s/%s' % (service.upper(), hostname)

        self._flags = ClientContextReq.integrity | ClientContextReq.replay_detect | \
            ClientContextReq.sequence_detect | ClientContextReq.mutual_auth

        if delegate:
            self._flags |= ClientContextReq.delegate

        if confidentiality:
            self._flags |= ClientContextReq.confidentiality

        auth_data = None
        if username:
            auth_data = WinNTAuthIdentity(username, domain, password)

        self._attr_sizes = None
        self._completed = False
        self._credential = acquire_credentials_handle(None, protocol, auth_data=auth_data)
        self._context = SSPISecContext()
        self.__seq_num = 0

    @classmethod
    def supported_protocols(cls):
        return ['kerberos', 'negotiate', 'ntlm']

    @property
    def complete(self):
        return self._completed

    @property
    @requires_context
    def session_key(self):
        return query_context_attributes(self._context, SecPkgAttr.session_key)

    def step(self):
        in_token = None
        while not self.complete:
            out_token = self._step(in_token)
            log.debug("InitializeSecurityContext output: %s", to_text(base64.b64encode(out_token)))

            in_token = yield out_token if out_token else None
            log.debug("InitializeSecurityContext input: %s", to_text(base64.b64encode(in_token)))

        # FIXME: requests-credssp has this.
        yield None

    @requires_context
    def wrap(self, data, confidential=True):
        qop = 0 if confidential else 0x80000001  # SECQOP_WRAP_NO_ENCRYPT

        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.token, b"\x00" * self._attr_sizes.security_trailer),
            SecBuffer(SecBufferType.data, data),
            SecBuffer(SecBufferType.padding, b"\x00" * self._attr_sizes.block_size),
        ])
        encrypt_message(self._context, buffer, seq_no=self._seq_num, qop=qop)

        return buffer[0].buffer, buffer[1].buffer, buffer[2].buffer

    @requires_context
    def wrap_iov(self, *iov, confidential=True):
        raise NotImplementedError()

    @requires_context
    def unwrap(self, data):
        buffer = SecBufferDesc([
            SecBuffer(SecBufferType.stream, data),
            SecBuffer(SecBufferType.data, alloc_type='pointer'),
        ])
        decrypt_message(self._context, buffer, seq_no=self._seq_num)

        return buffer[1].buffer

    @requires_context
    def unwrap_iov(self, *iov):
        raise NotImplementedError()

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _step(self, token):
        sec_tokens = []
        if token is not None:
            sec_tokens.append(SecBuffer(SecBufferType.token, token))
        if self.channel_bindings:
            sec_tokens.append(SecBuffer(SecBufferType.channel_bindings, self.channel_bindings))
        sec_buffer = SecBufferDesc(sec_tokens) if sec_tokens else None

        out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token, alloc_type='system')])

        try:
            res = initialize_security_context(self._credential, self._context, self._target_spn, self._flags,
                                              input_buffer=sec_buffer, output_buffer=out_buffer)
        except WindowsError as err:
            res = err.winerror
            rc_name = "Unknown Error"
            for name, value in vars(SecStatus).items():
                if isinstance(value, int) and name.startswith("SEC_") and value == res:
                    rc_name = name
                    break

            raise RuntimeError("InitializeSecurityContext failed: (%d) %s 0x%s - %s"
                               % (res, rc_name, format(res & 0xFFFFFFFF, '08X'), err.strerror))

        if res == SecStatus.SEC_E_OK:
            self._completed = True
            self._attr_sizes = query_context_attributes(self._context, SecPkgAttr.sizes)

        return out_buffer[0].buffer
