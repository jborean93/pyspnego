# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import gssapi
import logging

from gssapi.raw import acquire_cred_with_password
from gssapi.raw import set_sec_context_option
from gssapi.raw import inquire_sec_context_by_oid
from gssapi.raw import ChannelBindings

HAS_IOV = True
try:
    from gssapi.raw import (
        IOV,
        IOVBufferType,
        unwrap_iov,
        wrap_iov,
    )
except ImportError:
    HAS_IOV = False

from spnego._context import (
    SecurityContext,
    requires_context,
)

from spnego._text import (
    to_bytes,
    to_text,
)

log = logging.getLogger(__name__)

_KERBEROS_OID = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')
_NTLM_OID = gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10')
_SPNEGO_OID = gssapi.OID.from_int_seq('1.3.6.1.5.5.2')

_GSS_C_INQ_SSPI_SESSION_KEY = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2.5.5")

# https://github.com/simo5/gss-ntlmssp/blob/bfc7232dbb2259072a976fc9cdb6ae4bfd323304/src/gssapi_ntlmssp.h#L68
_GSS_NTLMSSP_RESET_CRYPTO_OID = gssapi.OID.from_int_seq('1.3.6.1.4.1.7165.655.1.3')


def _get_credential(mech, username=None, password=None):
    if username is not None:
        name_type = getattr(gssapi.NameType, 'kerberos_principal' if mech == _KERBEROS_OID else 'user')
        username = gssapi.Name(base=username, name_type=name_type)

    cred = None
    if mech == _KERBEROS_OID or (mech == _SPNEGO_OID and not (username or password)):
        try:
            cred = gssapi.Credentials(name=username, usage='initial', mechs=[mech])

            # Raises ExpiredCredentialsError if it has expired, we don't care about the actual value.
            _ = cred.lifetime
        except gssapi.raw.GSSError:
            # If we can't acquire a cred from the cache then we need an explicit password so raise the cache error
            # if none is set.
            if password is None:
                raise

            cred = None
    elif not (username or password):
        raise ValueError("Can only use implicit credentials with kerberos or negotiate authentication")

    if cred is None:
        cred = acquire_cred_with_password(username, to_bytes(password), usage='initiate', mechs=[mech]).creds

    return cred


class GSSAPI(SecurityContext):

    def __init__(self, username, password, hostname, service=None, channel_bindings=None, delegate=None,
                 confidentiality=True, protocol='negotiate'):
        super(GSSAPI, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                     confidentiality, protocol)

        mech = {
            'kerberos': _KERBEROS_OID,
            'negotiate': _SPNEGO_OID,
            'ntlm': _NTLM_OID
        }[protocol]

        flags = gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.out_of_sequence_detection
        if delegate:
            flags |= gssapi.RequirementFlag.delegate_to_peer
        if confidentiality:
            flags |= gssapi.RequirementFlag.confidentiality

        target_spn = gssapi.Name('%s@%s' % (service.lower(), hostname), name_type=gssapi.NameType.hostbased_service)
        cred = _get_credential(mech, username=username, password=password)
        self._context = gssapi.SecurityContext(name=target_spn, creds=cred, usage='initiate', mech=mech, flags=flags,
                                               channel_bindings=self.channel_bindings)

    @classmethod
    def supported_protocols(cls):
        protocols = ['kerberos']

        # While Heimdal on macOS has a valid NTLM implementation it doesn't seem to actually work. Their SPNEGO
        # implementation also fails when trying to acquire the credentials with the mech not being the Kerberos OID.
        # This should only support ntlm and negotiate if the gssapi_ntlmssp provider is installed as that is known to
        # work. We check its presence by creating a fake user context and see if it implements
        # GSS_NTLMSSP_RESET_CRYPTO_OID. Some recent commits to Heimdal seems to indicate this is now implemented in
        # there but macOS seems to be quite far behind.
        # TODO: Build Heimdal on Linux and see if this works.
        try:
            # This can be anything, the first NTLM message doesn't need a valid target name or credential.
            target_name = gssapi.Name('http@server', name_type=gssapi.NameType.hostbased_service)
            cred = _get_credential(_NTLM_OID, username='user', password='pass')

            context = gssapi.SecurityContext(name=target_name, creds=cred, usage='initiate', mech=_NTLM_OID)
            context.step()  # Need to at least have a context set up before we can call gss_set_sec_context_option.
            set_sec_context_option(_GSS_NTLMSSP_RESET_CRYPTO_OID, context=context, value=b"\x00\x00\x00\x00")

            protocols.extend(['negotiate', 'ntlm'])
        except gssapi.raw.GSSError as err:
            pass

        return protocols

    @property
    def complete(self):
        return self._context.complete

    @property
    @requires_context
    def session_key(self):
        return inquire_sec_context_by_oid(self._context, _GSS_C_INQ_SSPI_SESSION_KEY)[0]

    def step(self):
        in_token = None
        while not self.complete:
            out_token = self._context.step(in_token)
            log.debug("GSSAPI gss_init_sec_context() output: %s", to_text(base64.b64encode(out_token or b"")))

            in_token = yield out_token
            log.debug("GSSAPI gss_init_sec_context() input: %s", to_text(base64.b64encode(in_token)))

    @requires_context
    def wrap(self, data, confidential=True):
        return self._context.wrap(data, confidential).message

    @requires_context
    def wrap_iov(self, *iov, confidential=True):
        iov = IOV(*[(IOVBufferType(i[0]), i[1], i[2]) for i in iov], std_layout=False)
        wrap_iov(self._context, iov, confidential=confidential)
        return [i.value or b"" for i in iov]

    @requires_context
    def unwrap(self, data):
        return self._context.unwrap(data)[0]

    @requires_context
    def unwrap_iov(self, *iov):
        iov = IOV(*[(IOVBufferType(i[0]), i[1], i[2]) for i in iov], std_layout=False)
        unwrap_iov(self._context, iov)
        return [i.value or b"" for i in iov]

    @staticmethod
    def convert_channel_bindings(bindings):
        return ChannelBindings(initiator_address_type=bindings.initiator_addrtype,
                               initiator_address=bindings.initiator_address,
                               acceptor_address_type=bindings.acceptor_addrtype,
                               acceptor_address=bindings.acceptor_address,
                               application_data=bindings.application_data)
