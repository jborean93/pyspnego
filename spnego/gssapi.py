# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import gssapi
import logging

from gssapi.raw import (
    acquire_cred_with_password,
    ChannelBindings,
    exceptions as gss_errors,
    GSSError,
    inquire_sec_context_by_oid,
    set_sec_context_option,
)

from spnego._context import (
    SecurityContext,
    requires_context,
)

from spnego._text import (
    to_bytes,
    to_text,
)


HAS_IOV = True
IOV_ERR = None
try:
    from gssapi.raw import (
        IOV,
        IOVBufferType,
        unwrap_iov,
        wrap_iov,
    )
except ImportError as err:
    HAS_IOV = False
    IOV_ERR = str(err)


log = logging.getLogger(__name__)

_KERBEROS_OID = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')
_NTLM_OID = gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10')
_SPNEGO_OID = gssapi.OID.from_int_seq('1.3.6.1.5.5.2')

_GSS_C_INQ_SSPI_SESSION_KEY = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2.5.5")

# https://github.com/simo5/gss-ntlmssp/blob/bfc7232dbb2259072a976fc9cdb6ae4bfd323304/src/gssapi_ntlmssp.h#L68
_GSS_NTLMSSP_RESET_CRYPTO_OID = gssapi.OID.from_int_seq('1.3.6.1.4.1.7165.655.1.3')


def _check_ntlm_available():
    # While Heimdal on macOS has a valid NTLM implementation it doesn't seem to actually work. Their SPNEGO
    # implementation also fails when trying to acquire the credentials with the mech not being the Kerberos OID.
    # This should only support ntlm and negotiate if the gssapi_ntlmssp provider is installed as that is known to
    # work. We check its presence by creating a fake user context and see if it implements
    # GSS_NTLMSSP_RESET_CRYPTO_OID. Some recent commits to Heimdal seems to indicate this is now implemented in
    # there but macOS seems to be quite far behind.
    # TODO: Build Heimdal on Linux and see if this works.

    # Cache the result so we don't run this check multiple times.
    try:
        return _check_ntlm_available.result
    except AttributeError:
        pass

    avail = False
    try:
        # This can be anything, the first NTLM message doesn't need a valid target name or credential.
        target_name = gssapi.Name('http@server', name_type=gssapi.NameType.hostbased_service)
        cred = _get_credential(_NTLM_OID, 'initiate', username='user', password='pass')

        context = gssapi.SecurityContext(name=target_name, creds=cred, usage='initiate', mech=_NTLM_OID)
        context.step()  # Need to at least have a context set up before we can call gss_set_sec_context_option.
        set_sec_context_option(_GSS_NTLMSSP_RESET_CRYPTO_OID, context=context, value=b"\x00\x00\x00\x00")

        # gss-ntlmssp only added support for GSS_C_INQ_SSPI_SESSION_KEY in v0.8.0, we check to make sure we can
        # access this before declaring support for it. While we could live without this support to provide a common
        # interface across all provides we won't support Negotiate/NTLM.
        # https://github.com/gssapi/gss-ntlmssp/issues/10
        try:
            inquire_sec_context_by_oid(context, _GSS_C_INQ_SSPI_SESSION_KEY)
        except gss_errors.OperationUnavailableError as err:
            # (GSS_S_UNAVAILABLE | ERR_NOTAVAIL) is raised when ntlmssp does support GSS_C_INQ_SSPI_SESSION key but
            # the context is not yet established. Any of errors would mean this isn't supported and we can't use
            # the current version installed.
            # https://github.com/gssapi/gss-ntlmssp/blob/9d7a275a4d6494606fb54713876e4f5cbf4d1362/src/gss_sec_ctx.c#L1277
            if err.min_code != 1314127894:  # ERR_NOTAVAIL
                raise

        avail = True
    except GSSError as err:
        log.debug("GSSAPI does not support required NTLM interfaces: %s" % str(err))

    _check_ntlm_available.result = avail
    return avail


def _get_credential(mech, usage, username=None, password=None):
    if username is not None:
        if mech == _KERBEROS_OID:
            name_type = gssapi.NameType.kerberos_principal
        elif usage == 'initiate':
            name_type = gssapi.NameType.user
        else:
            name_type = gssapi.NameType.hostbased_service

        username = gssapi.Name(base=username, name_type=name_type)

    cred = None
    if mech == _KERBEROS_OID or (mech == _SPNEGO_OID and not (username or password)):
        try:
            cred = gssapi.Credentials(name=username, usage=usage, mechs=[mech])

            # Raises ExpiredCredentialsError if it has expired, we don't care about the actual value.
            _ = cred.lifetime
        except GSSError:
            # If we can't acquire a cred from the cache then we need an explicit password so raise the cache error
            # if none is set.
            if password is None:
                raise

            cred = None
    elif not (username or password):
        raise ValueError("Can only use implicit credentials with kerberos or negotiate authentication")

    if cred is None:
        cred = acquire_cred_with_password(username, to_bytes(password), usage=usage, mechs=[mech]).creds

    return cred


def _requires_iov(method):
    def wrapped(self, *args, **kwargs):
        if not HAS_IOV:
            raise RuntimeError("Function requires GSSAPI IOV extensions which is not available on this platform: %s"
                               % IOV_ERR)

        return method(self, *args, **kwargs)
    return wrapped


class _GSSAPI(SecurityContext):

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=None,
                 confidentiality=True, protocol='negotiate', is_client=True):
        super(_GSSAPI, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                      confidentiality, protocol)

        self._is_client = is_client
        self._mech = {
            'kerberos': _KERBEROS_OID,
            'negotiate': _SPNEGO_OID,
            'ntlm': _NTLM_OID
        }[protocol]

        self._flags = gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.out_of_sequence_detection
        if delegate:
            self._flags |= gssapi.RequirementFlag.delegate_to_peer
        if confidentiality:
            self._flags |= gssapi.RequirementFlag.confidentiality

        self._target_spn = gssapi.Name('%s@%s' % (service.lower(), hostname),
                                       name_type=gssapi.NameType.hostbased_service)

    @classmethod
    def supported_protocols(cls):
        protocols = ['kerberos']
        if _check_ntlm_available():
            protocols.extend(['negotiate', 'ntlm'])

        return protocols

    @property
    def complete(self):
        return self._context.complete

    @property
    @requires_context
    def session_key(self):
        return inquire_sec_context_by_oid(self._context, _GSS_C_INQ_SSPI_SESSION_KEY)[0]

    def step(self, in_token=None):
        method_name = 'gss_init_sec_context()' if self._is_client else 'gss_accept_sec_context()'

        if in_token:
            log.debug("GSSAPI %s input: %s", method_name, to_text(base64.b64encode(in_token)))

        out_token = self._context.step(in_token)
        log.debug("GSSAPI %s output: %s", method_name, to_text(base64.b64encode(out_token or b"")))

        return out_token

    @requires_context
    def wrap(self, data, confidential=True):
        return self._context.wrap(data, confidential).message

    @requires_context
    @_requires_iov
    def wrap_iov(self, iov, confidential=True):
        buffer = IOV(*self._build_iov(iov), std_layout=False)
        wrap_iov(self._context, buffer, confidential=confidential)
        return [i.value or b"" for i in buffer]

    @requires_context
    def wrap_winrm(self, data, confidential=True):
        # NTLM was used, either directly or through SPNEGO and gss-ntlmssp does not support wrap_iov, wrap works just
        # fine in this scenario as and the header is a fixed length with no padding.
        if self._context.mech == _NTLM_OID:
            enc_data = self.wrap(data, confidential=confidential)
            return enc_data[:16], enc_data[16:], b""

        return super(_GSSAPI, self).wrap_winrm(data, confidential=confidential)

    @requires_context
    def unwrap(self, data):
        return self._context.unwrap(data)[0]

    @requires_context
    @_requires_iov
    def unwrap_iov(self, iov):
        buffer = IOV(*self._build_iov(iov), std_layout=False)
        unwrap_iov(self._context, buffer)
        return tuple([i.value or b"" for i in buffer])

    @requires_context
    def unwrap_winrm(self, header, data):
        if self._context.mech == _NTLM_OID:
            return self.unwrap(header + data)

        return super(_GSSAPI, self).unwrap_winrm(header, data)

    def iov_buffer(self, buffer_type, data):
        auto_alloc = not data and buffer_type in [IOVBufferType.header, IOVBufferType.padding, IOVBufferType.trailer]
        return buffer_type, auto_alloc, data

    @staticmethod
    def convert_channel_bindings(bindings):
        return ChannelBindings(initiator_address_type=bindings.initiator_addrtype,
                               initiator_address=bindings.initiator_address,
                               acceptor_address_type=bindings.acceptor_addrtype,
                               acceptor_address=bindings.acceptor_address,
                               application_data=bindings.application_data)


class GSSAPIClient(_GSSAPI):

    def __init__(self, username, password, hostname, service='HOST', channel_bindings=None, delegate=None,
                 confidentiality=True, protocol='negotiate'):
        super(GSSAPIClient, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                           confidentiality, protocol)

        cred = _get_credential(self._mech, 'initiate', username=username, password=password)
        self._context = gssapi.SecurityContext(name=self._target_spn, creds=cred, usage='initiate', mech=self._mech,
                                               flags=self._flags, channel_bindings=self.channel_bindings)


class GSSAPIServer(_GSSAPI):

    def __init__(self, username, password, hostname, service='HOST', channel_bindings=None, delegate=None,
                 confidentiality=True, protocol='negotiate'):
        super(GSSAPIServer, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                           confidentiality, protocol, is_client=False)

        cred = _get_credential(self._mech, 'accept', username=username, password=password)
        self._context = gssapi.SecurityContext(creds=cred, usage='accept', channel_bindings=self.channel_bindings)
