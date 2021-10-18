# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import sys
import typing

from spnego._context import (
    ContextProxy,
    ContextReq,
    GSSMech,
    IOVUnwrapResult,
    IOVWrapResult,
    UnwrapResult,
    WinRMWrapResult,
    WrapResult,
    wrap_system_error,
)
from spnego._text import to_bytes, to_text
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import GSSError as NativeError
from spnego.exceptions import NegotiateOptions, SpnegoError
from spnego.iov import BufferType, IOVBuffer

log = logging.getLogger(__name__)

HAS_GSSAPI = True
GSSAPI_IMP_ERR = None
try:
    import gssapi
    import krb5
    from gssapi.raw import ChannelBindings, GSSError, acquire_cred_with_password
    from gssapi.raw import exceptions as gss_errors
    from gssapi.raw import inquire_sec_context_by_oid, set_sec_context_option
except ImportError as e:
    GSSAPI_IMP_ERR = str(e)
    HAS_GSSAPI = False
    log.debug("Python gssapi not available, cannot use any GSSAPIProxy protocols: %s" % e)


HAS_IOV = True
GSSAPI_IOV_IMP_ERR = None
try:
    from gssapi.raw import IOV, IOVBufferType, unwrap_iov, wrap_iov
except ImportError as err:
    GSSAPI_IOV_IMP_ERR = sys.exc_info()
    HAS_IOV = False
    log.debug("Python gssapi IOV extension not available: %s" % str(GSSAPI_IOV_IMP_ERR[1]))

_GSS_C_INQ_SSPI_SESSION_KEY = "1.2.840.113554.1.2.2.5.5"

# https://github.com/simo5/gss-ntlmssp/blob/bfc7232dbb2259072a976fc9cdb6ae4bfd323304/src/gssapi_ntlmssp.h#L68
_GSS_NTLMSSP_RESET_CRYPTO_OID = '1.3.6.1.4.1.7165.655.1.3'

# https://github.com/krb5/krb5/blob/master/src/lib/gssapi/spnego/spnego_mech.c#L483
_GSS_SPNEGO_REQUIRE_MIC_OID_STRING = '1.3.6.1.4.1.7165.655.1.2'


def _available_protocols(options: typing.Optional[NegotiateOptions] = None) -> typing.List[str]:
    """ Return a list of protocols that GSSAPIProxy can offer. """
    if not options:
        options = NegotiateOptions(0)

    protocols = []
    if HAS_GSSAPI:
        # We can't offer Kerberos if the caller requires WinRM wrapping and IOV isn't available.
        if not (options & NegotiateOptions.wrapping_winrm and not HAS_IOV):
            protocols = ['kerberos']

        # We can only offer NTLM if the mech is installed and can retrieve the functionality the caller desires.
        if _gss_ntlmssp_available(session_key=bool(options & NegotiateOptions.session_key)):
            protocols.append('ntlm')

        # We can only offer Negotiate if we can offer both Kerberos and NTLM.
        if len(protocols) == 2:
            protocols.append('negotiate')

    return protocols


def _create_iov_result(iov: "IOV") -> typing.Tuple[IOVBuffer, ...]:
    """ Converts GSSAPI IOV buffer to generic IOVBuffer result. """
    buffers = []
    for i in iov:
        buffer_entry = IOVBuffer(type=BufferType(i.type), data=i.value)
        buffers.append(buffer_entry)

    return tuple(buffers)


def _get_gssapi_credential(
    mech: "gssapi.OID",
    usage: str,
    username: typing.Optional[str] = None,
    password: typing.Optional[str] = None,
    context_req: typing.Optional[ContextReq] = None,
) -> typing.Optional["gssapi.creds.Credentials"]:
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
        context_req: Context requirement flags that can control how the credential is retrieved.

    Returns:
        gssapi.creds.Credentials: The credential set that was created/retrieved.

    .. _gss-ntlmssp:
        https://github.com/gssapi/gss-ntlmssp
    """
    principal = None
    if username:
        name_type = getattr(gssapi.NameType, 'user' if usage == 'initiate' else 'hostbased_service')
        principal = gssapi.Name(base=username, name_type=name_type)

    if principal and password:
        if usage == "initiate" and mech == gssapi.OID.from_int_seq(GSSMech.kerberos.value):
            # GSSAPI offers no way to specify custom flags like forwardable when getting a Kerberos credential. This
            # calls the Kerberos API to get the ticket and convert it to a GSSAPI credential.
            forwardable = bool(
                context_req and (context_req & ContextReq.delegate or context_req & ContextReq.delegate_policy)
            )
            cred = _kinit(to_bytes(username), to_bytes(password), forwardable=forwardable)
        else:
            # MIT krb5 < 1.14 would store the kerb cred in the global cache but later versions used a private cache in
            # memory. There's not much we can do about this but document this behaviour and hope people upgrade to a
            # newer version.
            cred = acquire_cred_with_password(principal, to_bytes(password), usage=usage, mechs=[mech]).creds

    elif principal or usage == 'accept':
        cred = gssapi.Credentials(name=principal, usage=usage, mechs=[mech])

        # We don't need to check the actual lifetime, just trying to get the valid will have gssapi check the lifetime
        # and raise an ExpiredCredentialsError if it is expired.
        _ = cred.lifetime

    else:
        # https://github.com/jborean93/pyspnego/issues/15
        # Using None as a credential when creating the sec context is better than getting the default credential as the
        # former takes into account the target SPN when selecting the principal to use.
        cred = None

    return cred


def _gss_ntlmssp_available(session_key: bool = False) -> bool:
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
        res = _gss_ntlmssp_available.result  # type: ignore
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
    except GSSError as gss_err:
        log.debug("GSSAPI does not support required the NTLM interfaces: %s" % str(gss_err))
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
            if getattr(o_err, 'min_code', 0) == 1314127894:  # ERR_NOTAVAIL
                ntlm_features['session_key'] = True

            else:
                log.debug("GSSAPI ntlmssp does not support session key interrogation: %s" % str(o_err))

    _gss_ntlmssp_available.result = ntlm_features  # type: ignore
    return _gss_ntlmssp_available(session_key=session_key)


def _gss_ntlmssp_reset_crypto(context: "gssapi.SecurityContext", outgoing: bool = True) -> None:
    """ Resets the NTLM RC4 ciphers when being used with SPNEGO. """
    reset_crypto = gssapi.OID.from_int_seq(_GSS_NTLMSSP_RESET_CRYPTO_OID)
    value = b"\x00\x00\x00\x00" if outgoing else b"\x01\x00\x00\x00"
    set_sec_context_option(reset_crypto, context=context, value=value)


def _gss_sasl_description(mech: "gssapi.OID") -> typing.Optional[bytes]:
    """ Attempts to get the SASL description of the mech specified. """
    try:
        res = _gss_sasl_description.result  # type: ignore
        return res[mech.dotted_form]

    except (AttributeError, KeyError):
        res = getattr(_gss_sasl_description, 'result', {})

    try:
        sasl_desc = gssapi.raw.inquire_saslname_for_mech(mech).mech_description
    except Exception as e:
        log.debug("gss_inquire_saslname_for_mech(%s) failed: %s" % (mech.dotted_form, str(e)))
        sasl_desc = None

    res[mech.dotted_form] = sasl_desc
    _gss_sasl_description.result = res  # type: ignore
    return _gss_sasl_description(mech)


def _kinit(
    username: bytes,
    password: bytes,
    forwardable: typing.Optional[bool] = None,
) -> "gssapi.raw.Creds":
    """Gets a Kerberos credential.

    This will get the GSSAPI credential that contains the Kerberos TGT inside
    it. This is used instead of gss_acquire_cred_with_password as the latter
    does not expose a way to request a forwardable ticket. This way makes it
    possible to request whatever is needed before making it usable in GSSAPI.

    Args:
        username: The username to get the credential for.
        password: The password to use to retrieve the credential.
        forwardable: Whether to request a forwardable credential.

    Returns:
        gssapi.raw.Creds: The GSSAPI credential for the Kerberos mech.
    """
    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, username)
    init_opt = krb5.get_init_creds_opt_alloc(ctx)

    if hasattr(krb5, "get_init_creds_opt_set_default_flags"):
        # Heimdal requires this to be set in order to load the default options from krb5.conf. This follows the same
        # code that it's own gss_acquire_cred_with_password does.
        realm = krb5.principal_get_realm(ctx, princ)
        krb5.get_init_creds_opt_set_default_flags(ctx, init_opt, b"gss_krb5", realm)

    krb5.get_init_creds_opt_set_canonicalize(init_opt, True)
    if forwardable is not None:
        krb5.get_init_creds_opt_set_forwardable(init_opt, forwardable)

    cred = krb5.get_init_creds_password(ctx, princ, init_opt, password=password)

    mem_ccache = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, mem_ccache, princ)
    krb5.cc_store_cred(ctx, mem_ccache, cred)

    # acquire_cred_from is less dangerous than krb5_import_cred which uses a raw pointer to access the ccache. Heimdal
    # has only recently added this API (not in a release as of 2021) so there's a fallback to the latter API.
    if hasattr(gssapi.raw, "acquire_cred_from"):
        kerberos = gssapi.OID.from_int_seq(GSSMech.kerberos.value)
        gssapi_creds = gssapi.raw.acquire_cred_from(
            {b"ccache": b"MEMORY:" + mem_ccache.name},
            mechs=[kerberos],
            usage="initiate",
        ).creds

    else:
        gssapi_creds = gssapi.raw.Creds()
        gssapi.raw.krb5_import_cred(gssapi_creds, cache=mem_ccache.addr)

    return gssapi_creds


class GSSAPIProxy(ContextProxy):
    """GSSAPI proxy class for GSSAPI on Linux.

    This proxy class for GSSAPI exposes GSSAPI calls into a common interface for SPNEGO authentication. This context
    uses the Python gssapi library to interface with the gss_* calls to provider Kerberos, and potentially native
    ntlm/negotiate functionality.
    """
    def __init__(
        self,
        username: typing.Optional[str] = None,
        password: typing.Optional[str] = None,
        hostname: typing.Optional[str] = None,
        service: typing.Optional[str] = None,
        channel_bindings: typing.Optional[GssChannelBindings] = None,
        context_req: ContextReq = ContextReq.default,
        usage: str = 'initiate',
        protocol: str = 'negotiate',
        options: NegotiateOptions = NegotiateOptions.none,
        _is_wrapped: bool = False,
        **kwargs: typing.Any,
    ) -> None:

        if not HAS_GSSAPI:
            raise ImportError("GSSAPIProxy requires the Python gssapi library: %s" % GSSAPI_IMP_ERR)

        super(GSSAPIProxy, self).__init__(username, password, hostname, service, channel_bindings, context_req, usage,
                                          protocol, options, _is_wrapped)

        mech_str = {
            'kerberos': GSSMech.kerberos.value,
            'negotiate': GSSMech.spnego.value,
            'ntlm': GSSMech.ntlm.value,
        }[self.protocol]
        mech = gssapi.OID.from_int_seq(mech_str)

        cred = None
        try:
            cred = _get_gssapi_credential(mech, self.usage, username=username, password=password,
                                          context_req=context_req)
        except GSSError as gss_err:
            raise SpnegoError(base_error=gss_err, context_msg="Getting GSSAPI credential") from gss_err

        context_kwargs = {}

        if self.channel_bindings:
            context_kwargs['channel_bindings'] = ChannelBindings(
                initiator_address_type=self.channel_bindings.initiator_addrtype,
                initiator_address=self.channel_bindings.initiator_address,
                acceptor_address_type=self.channel_bindings.acceptor_addrtype,
                acceptor_address=self.channel_bindings.acceptor_address,
                application_data=self.channel_bindings.application_data
            )

        if self.usage == 'initiate':
            spn = "%s@%s" % (service.lower() if service else 'host', hostname or 'unspecified')
            context_kwargs['name'] = gssapi.Name(spn, name_type=gssapi.NameType.hostbased_service)
            context_kwargs['mech'] = mech
            context_kwargs['flags'] = self._context_req

        self._context = gssapi.SecurityContext(creds=cred, usage=self.usage, **context_kwargs)

    @classmethod
    def available_protocols(cls, options: typing.Optional[NegotiateOptions] = None) -> typing.List[str]:
        return _available_protocols(options=options)

    @classmethod
    def iov_available(cls) -> bool:
        # NOTE: Even if the IOV headers are unavailable, if NTLM was negotiated then IOV won't work. Unfortunately we
        # cannot determine that here as we may not know the protocol until after negotiation.
        return HAS_IOV

    @property
    def client_principal(self) -> typing.Optional[str]:
        # Looks like a bug in python-gssapi where the value still has the terminating null char.
        return to_text(self._context.initiator_name).rstrip('\x00') if self.usage == 'accept' else None

    @property
    def complete(self) -> bool:
        return self._context.complete

    @property
    def negotiated_protocol(self) -> typing.Optional[str]:
        try:
            # For an acceptor this can be blank until the first token is received
            oid = self._context.mech.dotted_form
        except AttributeError:
            return None

        return {
            GSSMech.kerberos.value: 'kerberos',
            GSSMech.ntlm.value: 'ntlm',

            # Only set until the negotiate process is complete, will change to one of the above once the context is
            # set up.
            GSSMech.spnego.value: 'negotiate',
        }.get(oid, 'unknown: %s' % self._context.mech.dotted_form)

    @property  # type: ignore
    @wrap_system_error(NativeError, "Retrieving session key")
    def session_key(self) -> bytes:
        return inquire_sec_context_by_oid(self._context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))[0]

    @wrap_system_error(NativeError, "Processing security token")
    def step(self, in_token: typing.Optional[bytes] = None) -> typing.Optional[bytes]:
        if not self._is_wrapped:
            log.debug("GSSAPI step input: %s", base64.b64encode(in_token or b"").decode())

        out_token = self._context.step(in_token)
        self._context_attr = int(self._context.actual_flags)

        if not self._is_wrapped:
            log.debug("GSSAPI step output: %s", base64.b64encode(out_token or b"").decode())

        return out_token

    @wrap_system_error(NativeError, "Wrapping data")
    def wrap(self, data: bytes, encrypt: bool = True, qop: typing.Optional[int] = None) -> WrapResult:
        res = gssapi.raw.wrap(self._context, data, confidential=encrypt, qop=qop)

        # gss-ntlmssp used to hardcode the conf_state=0 which results in encrpted=False. Because we know it is always
        # sealed we just manually set to True.
        # https://github.com/gssapi/gss-ntlmssp/pull/15
        encrypted = True if self.negotiated_protocol == 'ntlm' else res.encrypted

        return WrapResult(data=res.message, encrypted=encrypted)

    @wrap_system_error(NativeError, "Wrapping IOV buffer")
    def wrap_iov(
        self,
        iov: typing.List[IOVBuffer],
        encrypt: bool = True,
        qop: typing.Optional[int] = None,
    ) -> IOVWrapResult:
        iov_buffer = IOV(*self._build_iov_list(iov), std_layout=False)
        encrypted = wrap_iov(self._context, iov_buffer, confidential=encrypt, qop=qop)

        return IOVWrapResult(buffers=_create_iov_result(iov_buffer), encrypted=encrypted)

    def wrap_winrm(self, data: bytes) -> WinRMWrapResult:
        if self.negotiated_protocol == 'ntlm':
            # NTLM does not support IOV wrapping, luckily the header is a fixed size so we can split at that.
            wrap_result = self.wrap(data).data
            header = wrap_result[:16]
            enc_data = wrap_result[16:]
            padding = b""

        else:
            iov = self.wrap_iov([BufferType.header, data, BufferType.padding]).buffers
            header = iov[0].data
            enc_data = iov[1].data
            padding = iov[2].data or b""

        return WinRMWrapResult(header=header, data=enc_data + padding, padding_length=len(padding))

    @wrap_system_error(NativeError, "Unwrapping data")
    def unwrap(self, data: bytes) -> UnwrapResult:
        res = gssapi.raw.unwrap(self._context, data)

        # See wrap for more info.
        encrypted = True if self.negotiated_protocol == 'ntlm' else res.encrypted

        return UnwrapResult(data=res.message, encrypted=encrypted, qop=res.qop)

    @wrap_system_error(NativeError, "Unwrapping IOV buffer")
    def unwrap_iov(self, iov: typing.List[IOVBuffer]) -> IOVUnwrapResult:
        iov_buffer = IOV(*self._build_iov_list(iov), std_layout=False)
        res = unwrap_iov(self._context, iov_buffer)

        return IOVUnwrapResult(buffers=_create_iov_result(iov_buffer), encrypted=res.encrypted, qop=res.qop)

    def unwrap_winrm(self, header: bytes, data: bytes) -> bytes:
        # This is an extremely weird setup, we need to use gss_unwrap for NTLM but for Kerberos it depends on the
        # underlying provider that is used. Right now the proper IOV buffers required to work on both AES and RC4
        # encrypted only works for MIT KRB5 whereas Heimdal fails. It currently mandates a padding buffer of a
        # variable size which we cannot achieve in the way that WinRM encrypts the data. This is fixed in the source
        # code but until it is widely distributed we just need to use a way that is known to just work with AES. To
        # ensure that MIT works on both RC4 and AES we check the description which differs between the 2 implemtations.
        # It's not perfect but I don't know of another way to achieve this until more time has passed.
        # https://github.com/heimdal/heimdal/issues/739
        sasl_desc = _gss_sasl_description(self._context.mech)

        # https://github.com/krb5/krb5/blob/f2e28f13156785851819fc74cae52100e0521690/src/lib/gssapi/krb5/gssapi_krb5.c#L686
        if sasl_desc and sasl_desc == b'Kerberos 5 GSS-API Mechanism':
            # TODO: Should done when self.negotiated_protocol == 'kerberos', above explains why this can't be done yet.
            iov = self.unwrap_iov([
                (IOVBufferType.header, header),
                data,
                IOVBufferType.data
            ]).buffers
            return iov[1].data

        else:
            return self.unwrap(header + data).data

    @wrap_system_error(NativeError, "Signing message")
    def sign(self, data: bytes, qop: typing.Optional[int] = None) -> bytes:
        return gssapi.raw.get_mic(self._context, data, qop=qop)

    @wrap_system_error(NativeError, "Verifying message")
    def verify(self, data: bytes, mic: bytes) -> int:
        return gssapi.raw.verify_mic(self._context, data, mic)

    @property
    def _context_attr_map(self) -> typing.List[typing.Tuple[ContextReq, int]]:
        attr_map = [
            (ContextReq.delegate, 'delegate_to_peer'),
            (ContextReq.mutual_auth, 'mutual_authentication'),
            (ContextReq.replay_detect, 'replay_detection'),
            (ContextReq.sequence_detect, 'out_of_sequence_detection'),
            (ContextReq.confidentiality, 'confidentiality'),
            (ContextReq.integrity, 'integrity'),

            # Only present when the DCE extensions are installed.
            (ContextReq.identify, 'identify'),

            # Only present with newer versions of python-gssapi https://github.com/pythongssapi/python-gssapi/pull/218.
            (ContextReq.delegate_policy, 'ok_as_delegate'),
        ]
        attrs = []
        for spnego_flag, gssapi_name in attr_map:
            if hasattr(gssapi.RequirementFlag, gssapi_name):
                attrs.append((spnego_flag, getattr(gssapi.RequirementFlag, gssapi_name)))

        return attrs

    @property
    def _requires_mech_list_mic(self) -> bool:
        try:
            require_mic = gssapi.OID.from_int_seq(_GSS_SPNEGO_REQUIRE_MIC_OID_STRING)
            res = inquire_sec_context_by_oid(self._context, require_mic)
        except GSSError:
            # Not all gssapi mechs implement this OID, the other mechListMIC rules still apply but are calc elsewhere.
            return False
        else:
            return b"\x01" in res

    def _convert_iov_buffer(self, buffer: IOVBuffer) -> typing.Any:
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

    @wrap_system_error(NativeError, "NTLM reset crypto state")
    def _reset_ntlm_crypto_state(self, outgoing: bool = True) -> None:
        if self.negotiated_protocol == 'ntlm':
            _gss_ntlmssp_reset_crypto(self._context, outgoing=outgoing)
