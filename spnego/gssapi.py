# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import gssapi
import logging

from gssapi.raw import acquire_cred_with_password
from gssapi.raw import set_sec_context_option
from gssapi.raw import ChannelBindings

wrap_iov = None
try:
    from gssapi.raw import wrap_iov, IOV, IOVBufferType
except ImportError:
    pass

from spnego._context import (
    SecurityContext,
    requires_context,
)

from spnego._text import (
    to_bytes,
    to_text,
)

log = logging.getLogger(__name__)


class GSSAPI(SecurityContext):

    VALID_PROTOCOLS = {'negotiate', 'ntlm', 'kerberos'}

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=None,
                 confidentiality=None, protocol='negotiate'):

        if confidentiality and not wrap_iov:
            raise ValueError("The GSSAPI auth provider does not support confidentiality on this host.")

        super(GSSAPI, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                     confidentiality, protocol)

        # TODO: accept all these options.
        server_name = gssapi.Name('%s@%s' % (service, hostname), name_type=gssapi.NameType.hostbased_service)

        name_type = gssapi.NameType.kerberos_principal
        mech = {
            'kerberos': gssapi.OID.from_int_seq('1.2.840.113554.1.2.2'),
            'negotiate': gssapi.OID.from_int_seq('1.3.6.1.5.5.2'),
            'ntlm': gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10'),
        }[protocol]
        cred = gssapi.raw.acquire_cred_with_password(gssapi.Name(base=username, name_type=name_type),
                                                     to_bytes(password), usage='initiate', mechs=[mech]).creds

        flags = gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.out_of_sequence_detection | \
            gssapi.RequirementFlag.confidentiality

        self._context = gssapi.SecurityContext(name=server_name, creds=cred, usage='initiate', mech=mech, flags=flags,
                                               channel_bindings=self.channel_bindings)

    @property
    def complete(self):
        # FIXME: requests-credssp requires knowing early that the NTLM auth is complete before sending the last token.
        return self._context.complete

    @property
    @requires_context
    def session_key(self):
        session_key_oid = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2.5.5") # GSS_C_INQ_SSPI_SESSION_KEY
        context_data = gssapi.raw.inquire_sec_context_by_oid(self._context, session_key_oid)

        return context_data[0]

    def step(self):
        in_token = None
        while not self.complete:
            out_token = self._context.step(in_token)
            log.debug("GSSAPI gss_init_sec_context() output: %s", to_text(base64.b64encode(out_token or b"")))

            in_token = yield out_token
            log.debug("GSSAPI gss_init_sec_context() input: %s", to_text(base64.b64encode(in_token)))

        # FIXME: requests-credssp returns a final token with mechListMIC when using NTLM which yields nothing.

    @requires_context
    def wrap(self, data):
        # return self._context.wrap(data, True).message
        # TODO use self._context.wrap(data, True).message when self._context.mech == NTLM.
        # FIXME: requests-credssp doesn't use IOV, will need to see if this still works there.
        iov = IOV(IOVBufferType.header, data, IOVBufferType.padding, std_layout=False)
        wrap_iov(self._context, iov, confidential=True)
        return iov[0].value, iov[1].value + (iov[2].value or b"")

    @requires_context
    def unwrap(self, header, data):
        return self._context.unwrap(header + data)[0]

    @staticmethod
    def convert_channel_bindings(bindings):
        return ChannelBindings(initiator_address_type=bindings.initiator_addrtype,
                               initiator_address=bindings.initiator_address,
                               acceptor_address_type=bindings.acceptor_addrtype,
                               acceptor_address=bindings.acceptor_address,
                               application_data=bindings.application_data)
