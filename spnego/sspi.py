# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging
import sspi
import sspicon
import win32security

from spnego._context import (
    SecurityContext,
    requires_context,
    split_username,
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

        flags = sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_REPLAY_DETECT | sspicon.ISC_REQ_SEQUENCE_DETECT | \
            sspicon.ISC_REQ_MUTUAL_AUTH

        if delegate:
            flags |= sspicon.ISC_REQ_DELEGATE

        if confidentiality:
            flags |= sspicon.ISC_REQ_CONFIDENTIALITY

        self._context = sspi.ClientAuth(pkg_name=protocol, auth_info=(username, domain, self.password),
                                        targetspn='%s/%s' % (service.upper(), hostname), scflags=flags)
        self.__seq_num = 0

    @classmethod
    def supported_protocols(cls):
        return ['kerberos', 'negotiate', 'ntlm']

    @property
    def complete(self):
        return self._context.authenticated

    @property
    @requires_context
    def session_key(self):
        return self._context.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SESSION_KEY)

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

        buffer = win32security.PySecBufferDescType()
        buffer.append(win32security.PySecBufferType(self._attr_sizes['SecurityTrailer'], sspicon.SECBUFFER_TOKEN))
        buffer.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_DATA))
        buffer.append(win32security.PySecBufferType(self._attr_sizes['BlockSize'], sspicon.SECBUFFER_PADDING))
        buffer[1].Buffer = data

        self._context.ctxt.EncryptMessage(qop, buffer, self._seq_num)

        return buffer[0].Buffer + buffer[1].Buffer + buffer[2].Buffer

    @requires_context
    def wrap_iov(self, *iov, confidential=True):
        raise NotImplementedError()

    @requires_context
    def unwrap(self, data):
        # Causes a heap corruption error, using a custom build that allows you to pass in a bool to avoid the buffer
        # being freed.
        # https://github.com/mhammond/pywin32/issues/1498
        buffer = win32security.PySecBufferDescType()
        buffer.append(win32security.PySecBufferType(len(data), sspicon.SECBUFFER_STREAM))
        buffer.append(win32security.PySecBufferType(0, sspicon.SECBUFFER_DATA, False))
        buffer[0].Buffer = data

        self._context.ctxt.DecryptMessage(buffer, self._seq_num)

        return buffer[1].Buffer

    @requires_context
    def unwrap_iov(self, *iov):
        raise NotImplementedError()

    @property
    def _seq_num(self):
        num = self.__seq_num
        self.__seq_num += 1
        return num

    def _step(self, token):
        success_codes = [
            sspicon.SEC_E_OK,
            sspicon.SEC_I_CONTINUE_NEEDED
        ]

        sec_tokens = []
        if token is not None:
            sec_token = win32security.PySecBufferType(self._context.pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
            sec_token.Buffer = token
            sec_tokens.append(sec_token)
        if self.channel_bindings:
            sec_token = win32security.PySecBufferType(len(self.channel_bindings), sspicon.SECBUFFER_CHANNEL_BINDINGS)
            sec_token.Buffer = self.channel_bindings
            sec_tokens.append(sec_token)

        if len(sec_tokens) > 0:
            sec_buffer = win32security.PySecBufferDescType()
            for sec_token in sec_tokens:
                sec_buffer.append(sec_token)
        else:
            sec_buffer = None

        rc, out_buffer = self._context.authorize(sec_buffer_in=sec_buffer)
        if rc not in success_codes:
            rc_name = "Unknown Error"
            for name, value in vars(sspicon).items():
                if isinstance(value, int) and name.startswith("SEC_") and \
                        value == rc:
                    rc_name = name
                    break

            raise RuntimeError("InitializeSecurityContext failed: (%d) %s 0x%s" % (rc, rc_name, format(rc, '08X')))
        elif rc == sspicon.SEC_E_OK:
            self._attr_sizes = self._context.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)

        return out_buffer[0].Buffer
