# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import logging

from collections import namedtuple

from ntlm_auth.gss_channel_bindings import (
    GssChannelBindingsStruct,
)

from ntlm_auth.ntlm import (
    NtlmContext,
)

from ntlm_auth.session_security import (
    SessionSecurity,
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
    NegTokenInit,
    NegTokenInit2,
    NegTokenResp,
    pack_mech_type_list,
    pack_neg_token_init,
    pack_neg_token_init2,
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
    GSSError = None


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

# https://github.com/krb5/krb5/blob/master/src/lib/gssapi/spnego/spnego_mech.c#L483
_GSS_SPNEGO_REQUIRE_MIC_OID_STRING = '1.3.6.1.4.1.7165.655.1.2'

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
        _reset_ntlm_crypto_state(context)

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


def _mech_requires_mech_list_mic(context):
    """
    NTLM on MS SPNEGO requires a mechListMIC if the NTLM Authentication msg contains its own MIC. By calling
    gss_inquire_sec_context_by_oid(GSS_SPNEGO_REQUIRE_MIC_OID_STRING) we first tell ntlmssp that it's ok to generate
    the MIC, then once the context is complete it returns b"\x01" if a MIC was actually generated.

    https://github.com/krb5/krb5/blob/b2fe66fed560ae28917a4acae6f6c0f020156353/src/lib/gssapi/spnego/spnego_mech.c#L493

    :param context: The gssapi security context to query.
    :return: Bool whether a MIC is required or not.
    """
    if isinstance(context, _NTLMProxy):
        return context.mic_present

    try:
        require_mic = gssapi.OID.from_int_seq(_GSS_SPNEGO_REQUIRE_MIC_OID_STRING)
        res = inquire_sec_context_by_oid(context, require_mic)
    except GSSError:
        # Not all gssapi mech's implement this OID, we treat those as not explicitly requiring a mechListMIC.
        return False
    else:
        return b"\x01" in res


def _reset_ntlm_crypto_state(context, outgoing=True):
    """
    When NTLM was negotiated with NTLM the original crypto state needs to be reset once the mechListMIC has been
    processed. This is a no-op for a context that is not NTLM.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/b87587b3-9d72-4027-8131-b76b5368115f

    :param context: The security context to reset the crypto state for.
    :param outgoing: Whether to reset the signer or verifier crypto state.
    """
    if isinstance(context, _NTLMProxy):
        context.reset_rc4_state(outgoing=outgoing)

    elif context.mech.dotted_form == _NTLM_OID:
        reset_crypto = gssapi.OID.from_int_seq(_GSS_NTLMSSP_RESET_CRYPTO_OID)
        value = b"\x00\x00\x00\x00" if outgoing else b"\x01\x00\x00\x00"
        set_sec_context_option(reset_crypto, context=context, value=value)


def _requires_iov(method):
    def wrapped(self, *args, **kwargs):
        if not HAS_IOV:
            raise RuntimeError("Function requires GSSAPI IOV extensions which is not available on this platform: %s"
                               % IOV_ERR)

        return method(self, *args, **kwargs)
    return wrapped


def _spnego_build_response(spnego_context, mech_token=None, mech_list_mic=None, is_client=True):
    if not spnego_context.init_sent:
        spnego_context.init_sent = True
        if is_client:
            return pack_neg_token_init(spnego_context.mech_list, mech_token=mech_token, mech_list_mic=mech_list_mic)
        else:
            return pack_neg_token_init2(spnego_context.mech_list, mech_token=mech_token, mech_list_mic=mech_list_mic)

    if not spnego_context.complete:
        # As per RFC 4178 - 4.2.2: supportedMech should only be present in the first reply from the target.
        # https://tools.ietf.org/html/rfc4178#section-4.2.2
        supported_mech = None
        if not spnego_context.mech_sent:
            supported_mech = spnego_context.mech
            spnego_context.mech_sent = True

        state = NegState.accept_incomplete

        if spnego_context.inner_context.complete:
            if spnego_context.mic_sent and not spnego_context.mic_recv:
                # TODO: request_mic for an acceptor should also be set if the preferred mech wasn't selected by the initiator
                state = NegState.request_mic
            else:
                state = NegState.accept_complete
                spnego_context.complete = True

        return pack_neg_token_resp(neg_state=state, response_token=mech_token, supported_mech=supported_mech,
                                   mech_list_mic=mech_list_mic)


def _spnego_process_mic(spnego_context, mech_list_mic):
    if mech_list_mic:
        spnego_context.inner_context.verify_signature(spnego_context.pack_mech_list(), mech_list_mic)
        _reset_ntlm_crypto_state(spnego_context.inner_context, outgoing=False)

        spnego_context.mic_required = True  # If we received a mechListMIC we need to send one back.
        spnego_context.mic_recv = True

    if spnego_context.mic_required and not spnego_context.mic_sent:
        out_mic = spnego_context.inner_context.get_signature(spnego_context.pack_mech_list())
        _reset_ntlm_crypto_state(spnego_context.inner_context)

        spnego_context.mic_sent = True

        return out_mic


class _NTLMProxy:
    """ This is a proxy class to make the interfaces of NtlmContext more like gssapi SecurityContext objects. """

    _WrapResult = namedtuple('WrapResult', ['message'])

    def __init__(self, ntlm_context):
        self.actual_flags = 0
        self._context = ntlm_context

    @property
    def complete(self):
        return self._context.complete

    @property
    def mech(self):
        class MechProxy:
            dotted_form = _NTLM_OID

        return MechProxy()

    @property
    def mic_present(self):
        # ntlm-auth only added the mic_present attribute in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        if hasattr(self._context, 'mic_present'):
            return self._context.mic_present

        if self._context._authenticate_message:
            return bool(self._context._authenticate_message.mic)

        return False

    @property
    def session_key(self):
        # session_key was only recently added in ntlm-auth, we have the fallback to the non-public interface for
        # older versions where we know this still works. This should be removed once ntlm-auth raises the min
        # version to (>=1.4.0).
        return getattr(self._context, 'session_key', self._context._session_security.exported_session_key)

    def step(self, in_token=None):
        if not in_token:
            out_token = self._context.step()
        else:
            out_token = self._context.step(in_token)

        if self.complete:
            # ntlm-auth only supports a set amount of features
            self.actual_flags = _BASE_CONTEXT_FLAG_MAP['confidentiality'] | \
                                _BASE_CONTEXT_FLAG_MAP['integrity'] | \
                                _BASE_CONTEXT_FLAG_MAP['replay_detect'] | \
                                _BASE_CONTEXT_FLAG_MAP['sequence_detect']

        return out_token

    def wrap(self, data, confidential):
        if not confidential:
            raise NotImplementedError("NtlmContext does not support non-confidential wrapping")

        return self._WrapResult(message=self._context.wrap(data))

    def unwrap(self, data):
        return self._WrapResult(message=self._context.unwrap(data))

    def get_signature(self, data):
        # ntlm-auth only added the sign function in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        return getattr(self._context, 'sign', self._context._session_security._get_signature)(data)

    def verify_signature(self, data, signature):
        # ntlm-auth only added the verify function in v1.5.0. We try and get the value from there and fallback
        # to a private interface we know is present on older versions.
        return getattr(self._context, 'verify', self._context._session_security._verify_signature)(data, signature)

    def reset_rc4_state(self, outgoing=True):
        # ntlm-auth only added the reset_rc4_state method in v1.5.0. We try and use that method if present and fallback
        # to an internal mechanism we know will work with older versions.
        if hasattr(self._context, 'reset_rc4_state'):
            self._context.reset_rc4_state(outgoing=outgoing)
        else:
            existing_ss = self._context._session_security

            # Can't just copy the keys, we need to derive the RC4 handle from the session_key so just recreate the obj.
            new_ss = SessionSecurity(existing_ss.negotiate_flags, self.session_key)
            new_ss.outgoing_seq_num = existing_ss.outgoing_seq_num
            new_ss.incoming_seq_num = existing_ss.incoming_seq_num

            self._context._session_security = new_ss


class _SPNEGOContext:

    def __init__(self, *mechs):
        self.mech_list = list(mechs)
        self.complete = False
        self.inner_context = None

        self.init_sent = False
        self.mech_sent = False
        self.mic_sent = False
        self.mic_recv = False
        self.mic_required = False

        self._mech = None

    @property
    def mech(self):
        return self._mech or self.mech_list[0]

    @mech.setter
    def mech(self, value):
        self._mech = value

    def pack_mech_list(self):
        """
        To calculate the mechListMIC we need to add a MIC based on the DER encoded value of the mechTypes entry in the
        initial request.

        :return: A byte string of the DER encoded mechTypes entry for the SPNEGO context that is being established.
        """
        # The input message is the DER encoding of the value of type MechTypeList "mechTypes" in the
        # NegTokenInit. The GSS_GetMIC() method is called to calculate that with the established context
        return pack_mech_type_list(self.mech_list)


class _GSSAPI(SecurityContextBase):

    _CONTEXT_FLAG_MAP = _BASE_CONTEXT_FLAG_MAP

    def __init__(self, username, password, hostname=None, service=None, channel_bindings=None, delegate=False,
                 mutual_auth=True, replay_detect=True, sequence_detect=True, confidentiality=True, integrity=True,
                 protocol='negotiate', feature_flags=0, is_client=True):
        super(_GSSAPI, self).__init__(username, password, hostname, service, channel_bindings, delegate, mutual_auth,
                                      replay_detect, sequence_detect, confidentiality, integrity, protocol, is_client)

        if not HAS_IOV and feature_flags & FeatureFlags.WRAPPING_IOV:
            raise FeatureMissingError(FeatureFlags.WRAPPING_IOV)

        # Determines whether to use our customer SPNEGO wrapper or just rely on the context.
        self._spnego_context = None

        # Determines whether we can rely on NTLM through gssapi or not.
        ntlm_available = _gss_ntlmssp_available(session_key=bool(feature_flags & FeatureFlags.SESSION_KEY))
        gssapi_mech = None

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

        elif not HAS_GSSAPI or (not HAS_IOV and feature_flags & FeatureFlags.WRAPPING_WINRM):
            # Either gssapi is not installed or the IOV headers are available and the caller requires WinRM encryption.
            # We can only use NTLM auth in this case but still wrap it in SPNEGO because they specified negotiate.
            # We should also raise FeatureMissingError if the caller has requested that Kerberos was at least available
            # for negotiation.
            if feature_flags & FeatureFlags.NEGO_KERBEROS:
                raise FeatureMissingError(FeatureFlags.NEGO_KERBEROS)

            self._spnego_context = _SPNEGOContext(_NTLM_OID)
            if ntlm_available:
                gssapi_mech = gssapi.OID.from_int_seq(_NTLM_OID)

        elif ntlm_available:
            # Both Kerberos and NTLM are available through gssapi, we can rely on it to do the full SPNEGO negotiation.
            gssapi_mech = gssapi.OID.from_int_seq(SPNEGO_OID)

        else:
            # NTLM is not available through gssapi, try and use Kerberos first and then fallback to ntlm-auth later
            # if that fails.
            self._spnego_context = _SPNEGOContext(_KERBEROS_OID, _NTLM_OID)
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
                # TODO: Check this error condition and validate it's ok.
                # If we are doing our own SPNEGO wrapping, ignore the error and fallback to ntlm-auth.
                if not self._spnego_context:
                    raise

                log.debug("Failed to generate GSSAPI credential and context for SPNEGO, falling back to NTLM: %s"
                          % str(err))

        if not self._context:
            self._context_provider = 'ntlm'

            domain, username = split_username(username)
            self._context = _NTLMProxy(NtlmContext(username, password, domain=domain))

        if self._spnego_context:
            self._spnego_context.inner_context = self._context

    @property
    def complete(self):
        if self._spnego_context:
            return self._spnego_context.complete
        else:
            return self._context.complete

    @property
    @requires_context
    def negotiated_protocol(self):
        return {
            _KERBEROS_OID: 'kerberos',
            _NTLM_OID: 'ntlm',
        }.get(self._context.mech.dotted_form, "unknown: %s" % self._context.mech.dotted_form)

    @property
    @requires_context
    def session_key(self):
        if self._context_provider == 'ntlm':
            return self._context.session_key
        else:
            return inquire_sec_context_by_oid(self._context, gssapi.OID.from_int_seq(_GSS_C_INQ_SSPI_SESSION_KEY))[0]

    def step(self, in_token=None):
        method_name = 'gss_init_sec_context()' if self._is_client else 'gss_accept_sec_context()'
        log.debug("%s input: %s", method_name, to_text(base64.b64encode(in_token or b"")))

        if self._spnego_context:
            # We are using SPNEGO but cannot rely on GSSAPI to manage the wrapping either because gssapi isn't
            # available or it's NTLM implementation won't work.
            out_token = self._step_spnego(in_token=in_token)
        else:
            # Either SPNEGO isn't being used or we can rely on gssapi to do everything for us, just get the context
            # to handle the tokens.
            out_token = self._step_gssapi(in_token=in_token)

        log.debug("%s output: %s", method_name, to_text(base64.b64encode(out_token or b"")))
        return out_token

    def _step_spnego(self, in_token=None):
        """
        SPNEGO practically operates in 3 steps;

            1. Process the SPNEGO mechs to derive the underlying protocol to use.
            2. Use the underlying protocol to get the output tokens
            3. Process/Generate the SPNEGO MICs if necessary

        :param in_token:
        :return:
        """
        # Step 1. Process SPNEGO mechs
        mech_token_in = None
        mech_list_mic = None

        if in_token:
            in_token = unpack_neg_token(in_token)

            mech_list_mic = in_token.mech_list_mic

            # Windows can send NegTokenInit2 (seen with SMB) token if it initiated the auth process, the fields we care
            # about are still the same as NegTokenInit.
            if isinstance(in_token, (NegTokenInit, NegTokenInit2)):
                self._spnego_context.init_sent = True
                mech_token_in = in_token.mech_token

                mech_types = in_token.mech_types
                new_list = []
                for oid in mech_types:
                    if oid in self._spnego_context.mech_list:
                        new_list.append(oid)

                # Could not find a common mechanism with the server
                if not new_list:
                    raise Exception("Failed to negotiated negotiation protocol with server")

                if self._spnego_context.mech != new_list[0]:
                    a = ''  # TODO: adjust list accordingly and rebuild the context.

            elif isinstance(in_token, NegTokenResp):
                mech_token_in = in_token.response_token

                # If we have received the supported_mech then we don't need to send our own.
                if in_token.supported_mech:
                    # TODO: verify that the supported_mech is the one we originally sent.
                    self._spnego_context.mech_sent = True

                # Raise exception if we are rejected and have no error info (mechToken) that will give us more info.
                if in_token.neg_state == NegState.reject and not mech_token_in:
                    raise Exception("Received SPNEGO rejection")

                if in_token.neg_state == NegState.request_mic:
                    self._spnego_context.mic_required = True
                elif in_token.neg_state == NegState.accept_complete:
                    self._spnego_context.complete = True

        else:
            # We are starting the process and can build our own mech list
            self._spnego_context = _SPNEGOContext(_KERBEROS_OID, _NTLM_OID)
            self._spnego_context.inner_context = self._context

        # Step 2. Process the inner context tokens.
        mech_token_out = None
        if not self._spnego_context.inner_context.complete:
            try:
                mech_token_out = self._step_gssapi(in_token=mech_token_in)
            except GSSError as err:
                # TODO: Need the fallback from GSSAPI failing with Kerb to ntlm-auth if the first step fails
                raise err
            else:
                # NTLM has a special case where we need to tell it it's ok to generate the MIC and also determine if
                # it actually did set the MIC as that controls the mechListMIC for the SPNEGO token.
                if _mech_requires_mech_list_mic(self._spnego_context.inner_context):
                    self._spnego_context.mic_required = True

        # Step 3. Process / generate the mechListMIC and return the new SPNEGO token.
        out_mic = _spnego_process_mic(self._spnego_context, mech_list_mic)
        return _spnego_build_response(self._spnego_context, mech_token=mech_token_out, mech_list_mic=out_mic,
                                      is_client=self._is_client)

    def _step_gssapi(self, in_token=None):
        out_token = self._context.step(in_token)

        if self._context.complete:
            self._context_attr = int(self._context.actual_flags)

        return out_token

    @requires_context
    def wrap(self, data, confidential=True):
        return self._context.wrap(data, confidential).message

    @requires_context
    @_requires_iov
    def wrap_iov(self, iov, confidential=True):
        if self.negotiated_protocol == 'ntlm':
            raise NotImplementedError("NTLM does not support IOV wrapping")

        buffer = IOV(*self._build_iov(iov), std_layout=False)
        wrap_iov(self._context, buffer, confidential=confidential)
        return [i.value or b"" for i in buffer]

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
        return self._context.unwrap(data).message

    @requires_context
    @_requires_iov
    def unwrap_iov(self, iov):
        if self.negotiated_protocol == 'ntlm':
            raise NotImplementedError("NTLM does not support IOV wrapping")

        buffer = IOV(*self._build_iov(iov), std_layout=False)
        unwrap_iov(self._context, buffer)
        return tuple([i.value or b"" for i in buffer])

    @requires_context
    def unwrap_winrm(self, header, data):
        if self.negotiated_protocol == 'ntlm':
            return self.unwrap(header + data)

        return super(_GSSAPI, self).unwrap_winrm(header, data)

    @requires_context
    def sign(self, data):
        self._context.get_signature(data)

    @requires_context
    def verify(self, data, signature):
        self._context.verify_signature(data, signature)

    def _convert_channel_bindings(self, bindings):
        if self._context_provider == 'ntlm':
            cbt = GssChannelBindingsStruct()
            cbt[cbt.INITIATOR_ADDTYPE] = bindings.initiator_addrtype
            cbt[cbt.INITIATOR_ADDRESS] = bindings.initiator_address
            cbt[cbt.ACCEPTOR_ADDRTYPE] = bindings.acceptor_addrtype
            cbt[cbt.ACCEPTOR_ADDRESS] = bindings.acceptor_address
            cbt[cbt.APPLICATION_DATA] = bindings.application_data

            return cbt
        else:
            return ChannelBindings(initiator_address_type=bindings.initiator_addrtype,
                                   initiator_address=bindings.initiator_address,
                                   acceptor_address_type=bindings.acceptor_addrtype,
                                   acceptor_address=bindings.acceptor_address,
                                   application_data=bindings.application_data)

    def _create_spn(self, service, principal):
        return u'%s@%s' % (service.lower(), principal)

    def _iov_buffer(self, buffer_type, data):
        auto_alloc = not data and buffer_type in [IOVBufferType.header, IOVBufferType.padding, IOVBufferType.trailer]
        return buffer_type, auto_alloc, data


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
