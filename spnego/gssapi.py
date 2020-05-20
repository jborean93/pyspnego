# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import logging

from spnego._compat import (
    List,
    Optional,
    Tuple,
    Union,
)

from spnego._context import (
    ContextProxy,
    ContextReq,
    GSSMech,
    IOVWrapResult,
    IOVUnwrapResult,
    NegotiateOptions,
    UnwrapResult,
    WrapResult,
)

from spnego._text import (
    text_type,
    to_bytes,
    to_text,
)

from spnego.exceptions import (
    SpnegoError,
)

from spnego.iov import (
    BufferType,
    IOVBuffer,
)

HAS_GSSAPI = True
try:
    import gssapi

    from gssapi.raw import (
        acquire_cred_with_password,
        ChannelBindings,
        exceptions as gss_errors,
        GSSError,
        inquire_sec_context_by_oid,
        set_sec_context_option,
    )
except ImportError:
    HAS_GSSAPI = False


HAS_IOV = True
try:
    from gssapi.raw import (
        IOV,
        IOVBufferType,
        unwrap_iov,
        wrap_iov,
    )
except ImportError as err:
    HAS_IOV = False


log = logging.getLogger(__name__)

_GSS_C_INQ_SSPI_SESSION_KEY = "1.2.840.113554.1.2.2.5.5"

# https://github.com/simo5/gss-ntlmssp/blob/bfc7232dbb2259072a976fc9cdb6ae4bfd323304/src/gssapi_ntlmssp.h#L68
_GSS_NTLMSSP_RESET_CRYPTO_OID = '1.3.6.1.4.1.7165.655.1.3'

# https://github.com/krb5/krb5/blob/master/src/lib/gssapi/spnego/spnego_mech.c#L483
_GSS_SPNEGO_REQUIRE_MIC_OID_STRING = '1.3.6.1.4.1.7165.655.1.2'


def _available_protocols(options=None):  # type: (Optional[NegotiateOptions]) -> List[text_type, ...]
    """ Return a list of protocols that GSSAPIProxy can offer. """
    if not options:
        options = NegotiateOptions(0)

    protocols = []
    if HAS_GSSAPI:
        # We can't offer Kerberos if the caller requires WinRM wrapping and IOV isn't available.
        if not (options & NegotiateOptions.wrapping_winrm and not HAS_IOV):
            protocols = [u'kerberos']

        # We can only offer NTLM if the mech is installed and can retrieve the functionality the caller desires.
        if _gss_ntlmssp_available(session_key=bool(options & NegotiateOptions.session_key)):
            protocols.append(u'ntlm')

        # We can only offer Negotiate if we can offer both Kerberos and NTLM.
        if len(protocols) == 2:
            protocols.append(u'negotiate')

    return protocols


def _get_gssapi_credential(mech, usage, username=None, password=None):
    # type: (gssapi.OID, str, Optional[text_type], Optional[Union[str, bytes]]) -> gssapi.creds.Credentials
    """Gets a set of credential(s).

    Will get a set of GSSAPI credential(s) for the mech specified. If the username and password is specified then a new
    set of credentials are explicitly required for the mech specified. Otherwise the credentials are retrieved by the
    cache as defined by the mech.

    The behaviour of this function is highly dependent on the GSSAPI implementation installed as well as what NTLM mech
    is available. Here are some of the known behaviours of each mech.

    Kerberos:
        Works for any GSSAPI implementation. The cache is the CCACHE which can be managed with `kinit`.

    NTLM:
        Only works with MIT krb5 and requires `gss-ntlmssp`_ to be installed. The cache that this mech uses is either
        a plaintext file specified by `NTLM_USER_FILE` in the format `DOMAIN:USERNAME:PASSWORD` or
        `:USER_UPN@REALM:PASSWORD` or it can be configured with winbind to a standalone Samba setup or with AD.

    SPNEGO:
        To work properly it requires both Kerberos and NTLM to be available where the latter only works with MIT krb5,
        see `NTLM` for more details. It attempts to get a credential for the all the mechs that SPNEGO supports so it
        will retrieve a Kerberos cred then NTLM.

    Args:
        mech: The mech OID to get the credentials for.
        usage: Either `initiate` for a client context or `accept` for a server context.
        username: The username to get the credentials for, if omitted then the default user is gotten from the cache.
        password: The password for the user, if omitted then the cached credentials is retrieved.

    Returns:
        gssapi.creds.Credentials: The credential set that was created/retrieved.

    .. _gss-ntlmssp:
        https://github.com/gssapi/gss-ntlmssp
    """
    if username:
        name_type = getattr(gssapi.NameType, 'user' if usage == 'initiate' else 'hostbased_service')
        username = gssapi.Name(base=username, name_type=name_type)

    if username and password:
        # NOTE: MIT krb5 < 1.14 would store this cred in the global cache but later versions used a private cache in
        # memory. There's not much we can do about this but document this behaviour and hope people upgrade to a newer
        # version.
        cred = acquire_cred_with_password(username, to_bytes(password), usage=usage, mechs=[mech])
        return cred.creds

    cred = gssapi.Credentials(name=username, usage=usage, mechs=[mech])

    # We don't need to check the actual lifetime, just trying to get the valid will have gssapi check the lifetime and
    # raise an ExpiredCredentialsError if it is expired.
    _ = cred.lifetime

    return cred


def _gss_ntlmssp_available(session_key=False):  # type: (bool) -> bool
    """Determine if NTLM is available through GSSAPI.

    NTLM support through GSSAPI is a complicated story. Because we rely on NTLM being available for SPNEGO fallback
    when Kerberos doesn't work we need to make sure the currently installed provider will give us what we need.

    Here is the current lay of the land for each GSSAPI provider.

    MIT KRB5:
        MIT KRB5 does not have NTLM builtin but it can be added with the `gss-ntlmssp`_ provider. We check to make sure
        the NTLM mech is installed and implements the required functions that are needed for SPNEGO support.

        The `gss-ntlmssp`_ provider only recently added support for retrieving its session key in v0.9.0. Not all
        callers need this behaviour so the `session_key` arg can be used to do a further check on that if needed.

    Heimdal:
        There are 2 major variants for Heimdal; 1. macOS' implementation, and 2. the actual Heimdal distribution. Each
        build has builtin "support" for NTLM but so far they are not usable for this library because:

        * macOS' implementation doesn't produce valid tokens, they are rejected by the server.
        * Pure Heimdal `gss_acquire_cred_with_password` isn't implemented for NTLM, no explicit creds.
        * Doesn't seem to produce a NTLM v2 message so the strength is even less than what our Python impl can offer.
        * It is doubtful it implements the required functions that MIT KRB5 relies on to get SPNEGO working.

        Because of these reasons we don't consider NTLM usable through GSSAPI on Heimdal based setups.

    Args:
        session_key: Whether the caller will want access to the session key of the context.

    Returns:
        bool: Whether NTLM is available to use (True) or not (False).

    .. _gss-ntlmssp:
        https://github.com/gssapi/gss-ntlmssp
    """
    # Cache the result so we don't run this check multiple times.
    try:
        res = _gss_ntlmssp_available.result
        return res['session_key'] if session_key else res['available']
    except AttributeError:
        pass

    ntlm_features = {
        'available': False,
        'session_key': False,
    }

    # If any of these calls results in a GSSError we treat that as NTLM being unusable because these are standard
    # behaviours we expect to work.
    ntlm = gssapi.OID.from_int_seq(GSSMech.ntlm.value)
    try:
        # This can be anything, the first NTLM message doesn't need a valid target name or credential.
        spn = gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service)
        cred = _get_gssapi_credential(ntlm, 'initiate', username='user', password='pass')
        context = gssapi.SecurityContext(creds=cred, usage='initiate', name=spn, mech=ntlm)

        context.step()  # Need to at least have a context set up before we can call gss_set_sec_context_option.

        # macOS' Heimdal implementation will work up to this point but the end messages aren't actually valid. Luckily
        # it does not implement 'GSS_NTLMSSP_RESET_CRYPTO_OID' so by running this we can weed out that broken impl.
        _gss_ntlmssp_reset_crypto(context)

        ntlm_features['available'] = True
    except GSSError as err:
        log.debug("GSSAPI does not support required the NTLM interfaces: %s" % str(err))
    else:
        # gss-ntlmssp only recently added support for GSS_C_INQ_SSPI_SESSION_KEY in v0.9.0, we check if it is present
        # before declaring session_key support is there as it might control whether it is used or not.
        # https://github.com/gssapi/gss-ntlmssp/issues/10
        try:
            inquire_sec_context_by_oid(context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))
        except gss_errors.OperationUnavailableError as o_err:
            # (GSS_S_UNAVAILABLE | ERR_NOTAVAIL) is raised when ntlmssp does support GSS_C_INQ_SSPI_SESSION key but
            # the context is not yet established. Any other errors would mean this isn't supported and we can't use
            # the current version installed if we need session_key interrogation.
            # https://github.com/gssapi/gss-ntlmssp/blob/9d7a275a4d6494606fb54713876e4f5cbf4d1362/src/gss_sec_ctx.c#L1277
            if o_err.min_code == 1314127894:  # ERR_NOTAVAIL
                ntlm_features['session_key'] = True
            else:
                pass
                # log.debug("GSSAPI ntlmssp does not support session key interrogation: %s" % str(err))

    _gss_ntlmssp_available.result = ntlm_features
    return _gss_ntlmssp_available(session_key=session_key)


def _gss_ntlmssp_reset_crypto(context, outgoing=True):  # type: (gssapi.SecurityContext, bool) -> None
    """ Resets the NTLM RC4 ciphers when being used with SPNEGO. """
    reset_crypto = gssapi.OID.from_int_seq(_GSS_NTLMSSP_RESET_CRYPTO_OID)
    value = b"\x00\x00\x00\x00" if outgoing else b"\x01\x00\x00\x00"
    set_sec_context_option(reset_crypto, context=context, value=value)


def _wrap_error(context=None):  # type: (Optional[str]) -> any
    """Wraps a GSSAPI function to catch any GSSErrors.

    Wraps a function that can potentially raise a GSSError and converts it to the common SpnegoError that is exposed
    by this library. This is to ensure the context proxy functions raise a common set of errors rather than a specific
    error for the provider. The underlying error is preserved in the SpnegoError if the user wishes to inspect that.

    Args:
        context: An optional context message to add to the error if raised.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)

            except GSSError as gss_err:
                raise SpnegoError(base_error=gss_err, context_msg=context)

        return wrapper
    return decorator


class GSSAPIProxy(ContextProxy):
    """GSSAPI proxy class for GSSAPI on Linux.

    This proxy class for GSSAPI exposes GSSAPI calls into a common interface for SPNEGO authentication. This context
    uses the Python gssapi library to interface with the gss_* calls to provider Kerberos, and potentially native
    ntlm/negotiate functionality.

    Args:
    """
    def __init__(self, username=None, password=None, hostname=None, service=None, channel_bindings=None,
                 context_req=ContextReq.default, usage='initiate', protocol='negotiate', options=0, is_wrapped=False):
        super(GSSAPIProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                          protocol, options, is_wrapped)

        if not HAS_GSSAPI:
            raise Exception("Requires gssapi")

        mech_str = {
            'kerberos': GSSMech.kerberos.value,
            'negotiate': GSSMech.spnego.value,
            'ntlm': GSSMech.ntlm.value,
        }[self.protocol]
        mech = gssapi.OID.from_int_seq(mech_str)
        cred = _get_gssapi_credential(mech, self.usage, username=username, password=password)

        context_kwargs = {}
        if self.usage == 'initiate':
            context_kwargs['name'] = gssapi.Name(self.spn, name_type=gssapi.NameType.hostbased_service)
            context_kwargs['mech'] = mech
            context_kwargs['flags'] = self._context_req

            if self.channel_bindings:
                context_kwargs['channel_bindings'] = ChannelBindings(
                    initiator_address_type=self.channel_bindings.initiator_addrtype,
                    initiator_address=self.channel_bindings.initiator_address,
                    acceptor_address_type=self.channel_bindings.acceptor_addrtype,
                    acceptor_address=self.channel_bindings.acceptor_address,
                    application_data=self.channel_bindings.application_data
                )

        self._context = gssapi.SecurityContext(creds=cred, usage=self.usage, **context_kwargs)

    @classmethod
    def available_protocols(cls, options=None):
        return _available_protocols(options=options)

    @classmethod
    def iov_available(cls):
        # NOTE: Even if the IOV headers are unavailable, if NTLM was negotiated then IOV won't work. Unfortunately we
        # cannot determine that here as we may not know the protocol until after negotiation.
        return HAS_IOV

    @property
    def complete(self):
        return self._context.complete

    @property
    def negotiated_protocol(self):
        return {
            GSSMech.kerberos.value: u'kerberos',
            GSSMech.ntlm.value: u'ntlm',
        }.get(self._context.mech.dotted_form, u'unknown: %s' % self._context.mech.dotted_form)

    @property
    @_wrap_error("retrieving session key")
    def session_key(self):
        return inquire_sec_context_by_oid(self._context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))[0]

    @_wrap_error("process security token")
    def step(self, in_token=None):
        if not self._is_wrapped:
            log.debug("GSSAPI step input: %s", to_text(base64.b64encode(in_token or b"")))

        out_token = self._context.step(in_token)
        self._context_attr = int(self._context.actual_flags)

        if not self._is_wrapped:
            log.debug("GSSAPI step output: %s", to_text(base64.b64encode(out_token or b"")))

        return out_token

    def wrap(self, data, encrypt=True, qop=None):
        res = gssapi.raw.wrap(self._context, data, confidential=encrypt, qop=qop)

        # gss-ntlmssp used to hardcode the conf_state=0 which results in encrpted=False. Because we know it is always
        # sealed we just manually set to True.
        # https://github.com/gssapi/gss-ntlmssp/pull/15
        encrypted = True if self.negotiated_protocol == 'ntlm' else res.encrypted

        return WrapResult(data=res.message, encrypted=encrypted)

    def wrap_iov(self, iov, encrypt=True, qop=None):
        buffer = IOV(*self._build_iov_list(iov), std_layout=False)
        encrypted = wrap_iov(self._context, buffer, confidential=encrypt, qop=qop)

        return IOVWrapResult(buffers=self._create_iov_result(buffer), encrypted=encrypted)

    def unwrap(self, data):
        res = gssapi.raw.unwrap(self._context, data)

        # See wrap for more info.
        encrypted = True if self.negotiated_protocol == 'ntlm' else res.encrypted

        return UnwrapResult(data=res.message, encrypted=encrypted, qop=res.qop)

    def unwrap_iov(self, iov):
        buffer = IOV(*self._build_iov_list(iov), std_layout=False)
        res = unwrap_iov(self._context, buffer)

        return IOVUnwrapResult(buffers=self._create_iov_result(buffer), encrypted=res.encrypted, qop=res.qop)

    @_wrap_error("Signing message")
    def sign(self, data, qop=None):
        return gssapi.raw.get_mic(self._context, data, qop=qop)

    @_wrap_error("Verifying MIC")
    def verify(self, data, mic):
        return gssapi.raw.verify_mic(self._context, data, mic)

    @property
    def _context_attr_map(self):
        return [
            (ContextReq.delegate, gssapi.RequirementFlag.delegate_to_peer),
            (ContextReq.mutual_auth, gssapi.RequirementFlag.mutual_authentication),
            (ContextReq.replay_detect, gssapi.RequirementFlag.replay_detection),
            (ContextReq.sequence_detect, gssapi.RequirementFlag.out_of_sequence_detection),
            (ContextReq.confidentiality, gssapi.RequirementFlag.confidentiality),
            (ContextReq.integrity, gssapi.RequirementFlag.integrity),
            (ContextReq.anonymous, gssapi.RequirementFlag.anonymity),
            (ContextReq.identify, getattr(gssapi.RequirementFlag, 'identify', 8192)),  # Only available with DCE ext.
            (ContextReq.delegate_policy, 32768),  # GSS_C_DELEG_POLICY_FLAG, doesn't seem to be in python gssapi.
        ]

    @property
    def _requires_mech_list_mic(self):
        try:
            require_mic = gssapi.OID.from_int_seq(_GSS_SPNEGO_REQUIRE_MIC_OID_STRING)
            res = inquire_sec_context_by_oid(self._context, require_mic)
        except GSSError:
            # Not all gssapi mechs implement this OID, the other mechListMIC rules still apply but are calc elsewhere.
            return False
        else:
            return b"\x01" in res

    def _convert_iov_buffer(self, buffer):  # type: (IOVBuffer) -> Tuple[int, bool, Optional[bytes]]
        buffer_data = None
        buffer_alloc = False

        if isinstance(buffer.data, bytes):
            buffer_data = buffer.data
        elif isinstance(buffer.data, int):
            # This shouldn't really occur on GSSAPI but is here to mirror what SSPI does.
            buffer_data = b"\x00" * buffer.data
        else:
            auto_alloc = [BufferType.header, BufferType.padding, BufferType.trailer]

            buffer_alloc = buffer.data
            if buffer_alloc is None:
                buffer_alloc = buffer.type in auto_alloc

        return buffer.type, buffer_alloc, buffer_data

    def _create_iov_result(self, iov):  # type: (IOV) -> Tuple[IOVBuffer, ...]
        buffers = []
        for i in iov:
            buffer_entry = IOVBuffer(type=BufferType(i.type), data=i.value)
            buffers.append(buffer_entry)

        return tuple(buffers)

    def _create_spn(self, service, principal):
        return u"%s@%s" % (service.lower() if service else u'host', principal or u'unspecified')

    def _reset_ntlm_crypto_state(self, outgoing=True):
        if self.negotiated_protocol == u'ntlm':
            _gss_ntlmssp_reset_crypto(self._context, outgoing=outgoing)
