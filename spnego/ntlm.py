# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging

from ntlm_auth.gss_channel_bindings import (
    GssChannelBindingsStruct,
)

from ntlm_auth.ntlm import (
    NtlmContext,
)

from spnego._context import (
    SecurityContext,
    requires_context,
)

log = logging.getLogger(__name__)


class NTLM(SecurityContext):

    VALID_PROVIDERS = {'negotiate', 'ntlm'}

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=None,
                 confidentiality=None, provider='ntlm', workstation=None, ntlm_compatibility=3):
        """
        Generates an NTLM backed context through either raw NTLM or SPNEGO tokens.

        :param username: The username to authenticate with.
        :param password: The password for the user.
        :param hostname: This parameter is not used with this auth context.
        :param service: This parameter is not used with this auth context.
        :param channel_bindings: Optional channel_bindings.GssChannelBinding object.
        :param delegate: This parameter is not used with this auth context.
        :param confidentiality: This parameter is not used with this auth context.
        :param provider: The auth provider to use when creating authentication tokens, can be ntlm or negotiate.
            Setting to negotiate will just wrap the raw ntlm tokens in an SPNEGO token.
        :param workstation: Optional workstation name, used as a simple identifier.
        :param ntlm_compatibility: Set the Lan Manager Compatability level. This should be changed unless you really
            need backwards compatibility with insecure authentication protocols.

            0: LM and NTLMv1
            1: LM, NTLMv1, and NTLMv1 with Extended Session Security
            2: NTLMv1, and NTLMv1 with Extended Session Security
            3: NTLMv2 Only
        """
        super(NTLM, self).__init__(username, password, hostname, service, channel_bindings, delegate, confidentiality,
                                   provider)

        if username and not password:
            raise ValueError("Cannot use NTLM auth with explicit user and not password")

        # TODO: Look into adding anonymous support for NTLM auth in ntlm-auth.
        self._context = NtlmContext(self.username, self.password, domain=self.domain, workstation=workstation,
                                    cbt_data=self.channel_bindings, ntlm_compatibility=ntlm_compatibility)

    @property
    def complete(self):
        return self._context.complete

    @property
    @requires_context
    def session_key(self):
        # session_key was only recently added in ntlm-auth, we have the fallback to the non-public interface for older
        # versions where we know this still works. This should be removed once ntlm-auth raises the min version to
        # (>=1.4.0).
        return getattr(self._context, 'session_key', self._context._session_security.exported_session_key)

    def step(self):
        # TODO: wrap/unwrap each token in an SPNEGO structure when self.provider == 'negotiate'.
        msg1 = self._context.step()
        log.debug("NTLM Negotiate: %s", lambda: base64.b64encode(msg1))

        msg2 = yield msg1
        log.debug("NTLM Challenge: %s", lambda: base64.b64encode(msg2))

        msg3 = self._context.step(msg2)
        log.debug("NTLM Authenticate: %s", lambda: base64.b64encode(msg3))

        yield msg2

    @requires_context
    def wrap(self, data):
        wrapped_data = self._context.wrap(data)
        return wrapped_data[:16], wrapped_data[16:]

    @requires_context
    def unwrap(self, header, data):
        return self._context.unwrap(header + data)

    @staticmethod
    def convert_channel_bindings(bindings):
        cbt = GssChannelBindingsStruct()
        cbt[cbt.INITIATOR_ADDTYPE] = bindings.initiator_addrtype
        cbt[cbt.INITIATOR_ADDRESS] = bindings.initiator_address
        cbt[cbt.ACCEPTOR_ADDRTYPE] = bindings.acceptor_addrtype
        cbt[cbt.ACCEPTOR_ADDRESS] = bindings.acceptor_address
        cbt[cbt.APPLICATION_DATA] = bindings.application_data

        return cbt
