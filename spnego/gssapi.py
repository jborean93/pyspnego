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

from spnego.exceptions import (
    FeatureMissingError,
)

from spnego._context import (
    FeatureFlags,
    requires_context,
    SecurityContextBase,
    split_username,
)

from spnego._text import (
    to_bytes,
    to_text,
)

from spnego._spnego import (
    NegState,
    pack_neg_token_init,
    pack_neg_token_resp,
    SPNEGO_OID,
    unpack_neg_token,
)


HAS_GSSAPI = True
GSSAPI_ERR = None
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
except ImportError as err:
    HAS_GSSAPI = False
    GSSAPI_ERR = err


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

_KERBEROS_OID = '1.2.840.113554.1.2.2'
_NTLM_OID = '1.3.6.1.4.1.311.2.2.10'

_GSS_C_INQ_SSPI_SESSION_KEY = "1.2.840.113554.1.2.2.5.5"

# https://github.com/simo5/gss-ntlmssp/blob/bfc7232dbb2259072a976fc9cdb6ae4bfd323304/src/gssapi_ntlmssp.h#L68
_GSS_NTLMSSP_RESET_CRYPTO_OID = '1.3.6.1.4.1.7165.655.1.3'

if HAS_GSSAPI:
    _BASE_CONTEXT_FLAG_MAP = {
        'delegate': gssapi.RequirementFlag.delegate_to_peer,
        'mutual_auth': gssapi.RequirementFlag.mutual_authentication,
        'replay_detect': gssapi.RequirementFlag.replay_detection,
        'sequence_detect': gssapi.RequirementFlag.out_of_sequence_detection,
        'confidentiality': gssapi.RequirementFlag.confidentiality,
        'integrity': gssapi.RequirementFlag.integrity,
    }
else:
    # gssapi isn't available so we need to rely on a manual mapping. It doesn't really matter as ntlm-auth doesn't
    # actually use any of these values.
    _BASE_CONTEXT_FLAG_MAP = {
        'delegate': 1,
        'mutual_auth': 2,
        'replay_detect': 4,
        'sequence_detect': 8,
        'confidentiality': 16,
        'integrity': 32,
    }


def _gss_ntlmssp_available(session_key=False):
    """
    NTLM support through GSSAPI is a complicated story. Because we rely on NTLM being available for SPNEGO fallback
    when Kerberos doesn't work we need to make sure the currently installed provider will give us what we need.

    Here is the current lay of the land for each GSSAPI providers.

    MIT KRB5:
        MIT KRB5 does not have NTLM builtin but it can be added with the gss-ntlmssp provider. We check to make sure
        the NTLM mech is installed and allows us to retrieve the session key if the caller desires that behaviour.
    Heimdal:
        There are 2 major variants for Heimdal; 1. macOS' implementation, and 2. the actual Heimdal distribution. Each
        build has builtin "support" for NTLM but so far they are not usable for this library because;

        Pure Heimdal:
        * gss_acquire_cred_with_password does not work, need to figure out if this can be bypassed
        * I can get a cred from the cache (NTLM_USER_FILE) but it is suggested I could also rely on the Kerberos cache
        * TODO: investigate this a bit further and see if I can get it working.

        macOS Heimdal:
        * For some reason the auth token it generates is just invalid, no idea why yet but it's unusable

    :param session_key: Whether the caller needs access to the session key derived on an NTLM context.
    :return: True if the GSSAPI NTLM provider can be used or False.
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

    if not HAS_GSSAPI:
        _gss_ntlmssp_available.result = ntlm_features
        return _gss_ntlmssp_available(session_key=session_key)

    # If any of these calls results in a GSSError we treat that as NTLM being unusable because these are standard
    # behaviours we expect to work.
    ntlm = gssapi.OID.from_int_seq(_NTLM_OID)
    try:
        # This can be anything, the first NTLM message doesn't need a valid target name or credential.
        cred = _get_gssapi_credential(ntlm, 'initiate', username='user', password='pass')
        target_name = gssapi.Name('http@server', name_type=gssapi.NameType.hostbased_service)

        context = gssapi.SecurityContext(name=target_name, creds=cred, usage='initiate', mech=ntlm)
        context.step()  # Need to at least have a context set up before we can call gss_set_sec_context_option.

        # macOS' Heimdal implementation will work up to this point but the end messages aren't actually valid. Luckily
        # it does not implement 'GSS_NTLMSSP_RESET_CRYPTO_OID' so by running this we can weed out that broken impl.
        set_sec_context_option(gssapi.OID.from_int_seq(_GSS_NTLMSSP_RESET_CRYPTO_OID), context=context,
                               value=b"\x00\x00\x00\x00")

        ntlm_features['available'] = True
    except GSSError as err:
        log.debug("GSSAPI does not support required the NTLM interfaces: %s" % str(err))
    else:
        # gss-ntlmssp only recently added support for GSS_C_INQ_SSPI_SESSION_KEY in v0.9.0, we check if it is present
        # before declaring session_key support is there as it might control whether it is used or not.
        # https://github.com/gssapi/gss-ntlmssp/issues/10
        try:
            inquire_sec_context_by_oid(context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))
        except gss_errors.OperationUnavailableError as err:
            # (GSS_S_UNAVAILABLE | ERR_NOTAVAIL) is raised when ntlmssp does support GSS_C_INQ_SSPI_SESSION key but
            # the context is not yet established. Any other errors would mean this isn't supported and we can't use
            # the current version installed if we need session_key interrogation.
            # https://github.com/gssapi/gss-ntlmssp/blob/9d7a275a4d6494606fb54713876e4f5cbf4d1362/src/gss_sec_ctx.c#L1277
            if err.min_code == 1314127894:  # ERR_NOTAVAIL
                ntlm_features['session_key'] = True
            else:
                log.debug("GSSAPI ntlmssp does not support session key interrogation: %s" % str(err))

    _gss_ntlmssp_available.result = ntlm_features
    return _gss_ntlmssp_available(session_key=session_key)


def _get_gssapi_credential(mech, usage, username=None, password=None):
    """
    Will get the GSSAPI credential object for the mech specified. If the username and password is specified then the
    credentials are gotten for whatever mech is specified. Otherwise the credential for the user is retrieved from the
    cache as defined by the mech.

    The behaviour of this function is highly dependent on the GSSAPI implementation installed as well as what NTLM
    mech is (or is not installed). Here are the known behaviours of each mech.

    Kerberos:
        Works just fine on both MIT krb5 and Heimdal. The cache is the CCACHE which can be controlled with kinit.
    NTLM:
        MIT krb5 only, requires gss-ntlmssp to be installed. The cache that it uses is the file specified by the env
        var 'NTLM_USER_FILE' in the format 'DOMAIN:USERNAME:PASSWORD' or ':USER_UPN@REALM:PASSWORD'. If winbind is set
        up it will also attempt to use that.
    SPNEGO:
        Is meant to get a credential for all the mechs that are supported by SPNEGO (NTLM/Kerberos). Unfortunately on
        Heimdal it will fail to get the NTLM credentials unless it is in the default cache which for NTLM is the
        'NTLM_USER_FILE' file (maybe there's a winbind backing as well). This makes SPNEGO only really usable on MIT.

    MIT krb5 is the typical GSSAPI package on Linux distributions whereas Heimdal is on macOS and other BSD based
    distros. Nothing stops a user from compiling either package on whatever distro they want though.

    :param mech: The mech (OID) to get the credential for.
    :param usage: Whether the credential is for 'initiate' (client) or 'accept' (server) use.
    :param username: The username to get the credential for. If None then the default (first) credential in the cache
        is used if available.
    :param password: The password for username. If set then a new credential is gotten instead on relying on the cache.
    :return: gssapi.Credentials of the creds to use in the secuirt context.
    """
    if username:
        name_type = getattr(gssapi.NameType, 'user' if usage == 'initiate' else 'hostbased_service')
        username = gssapi.Name(base=username, name_type=name_type)

    if username and password:
        # NOTE: MIT krb5 < 1.14 would store this cred in the global cache but later versions used a private cache in
        # memory. There's not much we can do about this but document this behaviour and hope people upgrade to a newer
        # version.
        log.debug("gss_acquire_cred_with_password(%s, %s, %s)" % (username, usage, mech.dotted_form))
        cred = acquire_cred_with_password(username, to_bytes(password), usage=usage, mechs=[mech])
        return cred.creds

    log.debug("gss_acquire_cred(%s, %s, %s)" % (username, usage, mech.dotted_form))
    cred = gssapi.Credentials(name=username, usage=usage, mechs=[mech])

    # We don't need to check the actual lifetime, just trying to get the valid will have gssapi check the lifetime and
    # raise an ExpiredCredentialsError if it is expired.
    _ = cred.lifetime

    return cred


def _requires_iov(method):
    def wrapped(self, *args, **kwargs):
        if not HAS_IOV:
            raise RuntimeError("Function requires GSSAPI IOV extensions which is not available on this platform: %s"
                               % IOV_ERR)

        return method(self, *args, **kwargs)
    return wrapped


class _GSSAPI(SecurityContextBase):

    _CONTEXT_FLAG_MAP = _BASE_CONTEXT_FLAG_MAP

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate', feature_flags=0, is_client=True):
        super(_GSSAPI, self).__init__(username, password, hostname, service, channel_bindings, delegate, mutual_auth,
                                      replay_detect, sequence_detect, confidentiality, integrity, protocol, is_client)

        # Controls whether step() wraps the raw token (NTLM or Kerberos) inside an SPNEGO token.
        self._wrap_spnego = False
        gssapi_mech = None

        if not HAS_IOV and feature_flags & FeatureFlags.WRAPPING_IOV:
            raise FeatureMissingError(FeatureFlags.WRAPPING_IOV)

        # Determines whether we can rely on NTLM through gssapi or not.
        ntlm_available = _gss_ntlmssp_available(session_key=bool(feature_flags & FeatureFlags.SESSION_KEY))

        if self.protocol == 'kerberos':
            # We can only use pure Kerberos if gssapi is installed and if WinRM wrapping is required we also need the
            # IOV extension headers to be present.
            if not HAS_GSSAPI:
                raise GSSAPI_ERR  # Just raise the original import error for gssapi.

            if not HAS_IOV and feature_flags & FeatureFlags.WRAPPING_WINRM:
                raise FeatureMissingError(FeatureFlags.WRAPPING_WINRM)

            gssapi_mech = gssapi.OID.from_int_seq(_KERBEROS_OID)
        elif self.protocol == 'ntlm':
            # We can use gssapi if we have determine it is available and fir for purpose, otherwise just use ntlm-auth.
            if ntlm_available:
                gssapi_mech = gssapi.OID.from_int_seq(_NTLM_OID)
        elif not HAS_GSSAPI:
            # If gssapi is not installed then we cannot negotiate any protocol. We just need to use pure NTLM from
            # ntlm-auth wrapped in our own SPNEGO token messages. We should also raise FeatureMissingError if the
            # caller has requested that Kerberos was at least available for negotiation.
            if feature_flags & FeatureFlags.NEGO_KERBEROS:
                raise FeatureMissingError(FeatureFlags.NEGO_KERBEROS)

            self._wrap_spnego = True
        elif not HAS_IOV and feature_flags & FeatureFlags.WRAPPING_WINRM:
            # If WinRM wrapping is required and the IOV headers aren't present we can't use Kerberos. We need to check
            # if the NEGO_KERBEROS feature flag is set and fail as the caller intended for Kerberos to at least be
            # available for negotiations
            if feature_flags & FeatureFlags.NEGO_KERBEROS:
                raise FeatureMissingError(FeatureFlags.NEGO_KERBEROS)

            # Now determine if we can use gssapi's NTLM mech or just use ntlm-auth
            self._wrap_spnego = True
            if ntlm_available:
                gssapi_mech = gssapi.OID.from_int_seq(_NTLM_OID)
        elif ntlm_available:
            # Both Kerberos and NTLM are available through gssapi, we can rely on it to do the full SPNEGO negotiation.
            gssapi_mech = gssapi.OID.from_int_seq(SPNEGO_OID)
        else:
            # NTLM is not available through gssapi, try and use Kerberos first and then fallback to ntlm-auth later
            # if that fails.
            self._wrap_spnego = True
            gssapi_mech = gssapi.OID.from_int_seq(_KERBEROS_OID)

        self._context = None
        if gssapi_mech:
            self._context_provider = 'gssapi'

            try:
                usage = 'initiate' if self._is_client else 'accept'

                cred = _get_gssapi_credential(gssapi_mech, usage, username=username, password=password)

                context_kwargs = {}
                if is_client:
                    context_kwargs = {
                        # Note: Pure Heimdal will validate the SPN is in the form service@principal
                        'name': gssapi.Name(self._spn, name_type=gssapi.NameType.hostbased_service),
                        'mech': gssapi_mech,
                        'flags': self._context_req,
                    }

                self._context = gssapi.SecurityContext(creds=cred, usage=usage, channel_bindings=self.channel_bindings,
                                                       **context_kwargs)
            except GSSError as err:
                # If we are doing our own SPNEGO wrapping, ignore the error and fallback to ntlm-auth.
                if not self._wrap_spnego:
                    raise

                log.debug("Failed to generate GSSAPI credential and context for SPNEGO, falling back to NTLM: %s"
                          % str(err))

        if not self._context:
            self._context_provider = 'ntlm'

            domain, username = split_username(username)
            self._context = NtlmContext(username, password, domain=domain)

    @property
    def complete(self):
        # Both gssapi and ntlm-auth have a complete property on it's context object which we can safely get.
        return self._context.complete

    @property
    @requires_context
    def negotiated_protocol(self):
        if self._context_provider == 'ntlm':
            # We used ntlm-auth which only does ntlm.
            return 'ntlm'
        else:
            # We used gssapi which provides the mech used on the security context.
            return {
                _KERBEROS_OID: 'kerberos',
                _NTLM_OID: 'ntlm',
            }.get(self._context.mech.dotted_form, "unknown: %s" % self._context.mech.dotted_form)

    @property
    @requires_context
    def session_key(self):
        return getattr(self, '_session_key_%s' % self._context_provider)()

    def _session_key_gssapi(self):
        return inquire_sec_context_by_oid(self._context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))[0]

    def _session_key_ntlm(self):
        # session_key was only recently added in ntlm-auth, we have the fallback to the non-public interface for older
        # versions where we know this still works. This should be removed once ntlm-auth raises the min version to
        # (>=1.4.0).
        return getattr(self._context, 'session_key', self._context._session_security.exported_session_key)

    def step(self, in_token=None):
        if self._wrap_spnego and in_token:
             # TODO: Validate the neg token.
            neg_resp = unpack_neg_token(in_token)
            in_token = neg_resp.response_token

        try:
            token = getattr(self, '_step_%s' % self._context_provider)(in_token=in_token)
        except GSSError as err:
            # If negotiate was not used, or we are using pure gssapi SPNEGO do not fallback ntlm-auth
            if self.protocol != 'negotiate' or not self._wrap_spnego:
                raise

            log.debug("GSSAPI Negotiate failed with Kerberos auth: falling back to NTLM: %s" % str(err))

            domain, username = split_username(self.username)
            self._context_provider = 'ntlm'
            self._context = NtlmContext(username, self.password, domain=domain)
            token = self._step_ntlm(in_token=in_token)

        if self._wrap_spnego:
            if not in_token:
                mech_list = [_NTLM_OID] if token.startswith(b"NTLMSSP\x00") else [_KERBEROS_OID, _NTLM_OID]
                token = pack_neg_token_init(mech_list, mech_token=token)
            else:
                supported_mech = _NTLM_OID if token.startswith(b"NTLMSSP\x00") else _KERBEROS_OID
                # TODO: create mech_list_MIC.
                token = pack_neg_token_resp(neg_state=1, supported_mech=_NTLM_OID, response_token=token)

        return token

    def _step_gssapi(self, in_token=None):
        method_name = 'gss_init_sec_context()' if self._is_client else 'gss_accept_sec_context()'

        if in_token:
            log.debug("%s input: %s", method_name, to_text(base64.b64encode(in_token)))

        out_token = self._context.step(in_token)
        log.debug("%s output: %s", method_name, to_text(base64.b64encode(out_token or b"")))

        if self.complete:
            self._context_attr = int(self._context.actual_flags)

        return out_token

    def _step_ntlm(self, in_token=None):
        if not in_token:
            out_token = self._context.step()
            log.debug("NTLM Negotiate: %s", to_text(base64.b64encode(out_token)))
        else:
            log.debug("NTLM Challenge: %s", to_text(base64.b64encode(in_token)))
            out_token = self._context.step(in_token)
            log.debug("NTLM Authenticate: %s", to_text(base64.b64encode(out_token)))

        if self.complete:
            # ntlm-auth only supports a set amount of features
            self._context_attr = self._CONTEXT_FLAG_MAP['confidentiality'] | \
                                 self._CONTEXT_FLAG_MAP['replay_detect'] | \
                                 self._CONTEXT_FLAG_MAP['sequence_detect']

        return out_token

    @requires_context
    def wrap(self, data, confidential=True):
        return getattr(self, '_wrap_%s' % self._context_provider)(data, confidential=confidential)

    def _wrap_gssapi(self, data, confidential=True):
        return self._context.wrap(data, confidential).message

    def _wrap_ntlm(self, data, confidential=True):
        if not confidential:
            raise NotImplementedError("NTLMClient does not support non-confidential wrapping")

        return self._context.wrap(data)

    @requires_context
    def wrap_iov(self, iov, confidential=True):
        return getattr(self, '_wrap_iov_%s' % self._context_provider)(iov, confidential=confidential)

    @_requires_iov
    def _wrap_iov_gssapi(self, iov, confidential=True):
        buffer = IOV(*self._build_iov(iov), std_layout=False)
        wrap_iov(self._context, buffer, confidential=confidential)
        return [i.value or b"" for i in buffer]

    def _wrap_iov_ntlm(self, *iov, confidential=True):
        raise NotImplementedError("NTLM provider does not support IOV wrapping")

    @requires_context
    def wrap_winrm(self, data, confidential=True):
        # NTLM was used, either directly or through SPNEGO and gss-ntlmssp does not support wrap_iov, wrap works just
        # fine in this scenario as and the header is a fixed length with no padding.
        if self.negotiated_protocol == 'ntlm':
            wrapped_data = self.wrap(data, confidential=confidential)
            return wrapped_data[:16], wrapped_data[16:], b""

        return super(_GSSAPI, self).wrap_winrm(data, confidential=confidential)

    @requires_context
    def unwrap(self, data):
        return getattr(self, '_unwrap_%s' % self._context_provider)(data)

    def _unwrap_gssapi(self, data):
        return self._context.unwrap(data)[0]

    def _unwrap_ntlm(self, data):
        return self._context.unwrap(data)

    @requires_context
    def unwrap_iov(self, iov):
        return getattr(self, '_unwrap_iov_%s' % self._context_provider)(iov)

    @_requires_iov
    def _unwrap_iov_gssapi(self, iov):
        buffer = IOV(*self._build_iov(iov), std_layout=False)
        unwrap_iov(self._context, buffer)
        return tuple([i.value or b"" for i in buffer])

    def _unwrap_iov_ntlm(self, iov):
        raise NotImplementedError("NTLM provider does not support IOV wrapping")

    @requires_context
    def unwrap_winrm(self, header, data):
        if self.negotiated_protocol == 'ntlm':
            return self.unwrap(header + data)

        return super(_GSSAPI, self).unwrap_winrm(header, data)

    def _iov_buffer(self, buffer_type, data):
        if self._context_provider == 'ntlm':
            raise NotImplementedError("NTLM provider does not support IOV wrapping")

        auto_alloc = not data and buffer_type in [IOVBufferType.header, IOVBufferType.padding, IOVBufferType.trailer]
        return buffer_type, auto_alloc, data

    def _create_spn(self, service, principal):
        return u'%s@%s' % (service.lower(), principal)

    def _convert_channel_bindings(self, bindings):
        return getattr(self, '_convert_channel_bindings_%s' % self._context_provider)(bindings)

    def _convert_channel_bindings_gssapi(self, bindings):
        return ChannelBindings(initiator_address_type=bindings.initiator_addrtype,
                               initiator_address=bindings.initiator_address,
                               acceptor_address_type=bindings.acceptor_addrtype,
                               acceptor_address=bindings.acceptor_address,
                               application_data=bindings.application_data)

    def _convert_channel_bindings_ntlm(self, bindings):
        cbt = GssChannelBindingsStruct()
        cbt[cbt.INITIATOR_ADDTYPE] = bindings.initiator_addrtype
        cbt[cbt.INITIATOR_ADDRESS] = bindings.initiator_address
        cbt[cbt.ACCEPTOR_ADDRTYPE] = bindings.acceptor_addrtype
        cbt[cbt.ACCEPTOR_ADDRESS] = bindings.acceptor_address
        cbt[cbt.APPLICATION_DATA] = bindings.application_data

        return cbt


class GSSAPIClient(_GSSAPI):

    def __init__(self, username, password, hostname, service='HOST', channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate', feature_flags=0):
        super(GSSAPIClient, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                           mutual_auth, replay_detect, sequence_detect, confidentiality, integrity,
                                           protocol, feature_flags, is_client=True)


class GSSAPIServer(_GSSAPI):

    def __init__(self, username, password, hostname, service='HOST', channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate', feature_flags=0):

        if not HAS_GSSAPI:
            raise ValueError("Cannot create a server context without gssapi being installed")
        elif self.protocol == 'ntlm' and not _gss_ntlmssp_available():
            raise ValueError("Cannot create a service context with NTLM without gss-ntlmssp being installed")

        super(GSSAPIServer, self).__init__(username, password, hostname, service, channel_bindings, delegate,
                                           mutual_auth, replay_detect, sequence_detect, confidentiality, integrity,
                                           protocol, feature_flags, is_client=False)
