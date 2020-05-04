# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import enum

from abc import (
    ABCMeta,
    abstractmethod,
)

from collections import (
    namedtuple,
)

from typing import (
    List,
    Optional,
    Tuple,
)

from spnego.channel_bindings import (
    GssChannelBindings,
)

from spnego.iov import (
    IOVBuffer,
)

from spnego._text import (
    text_type,
    to_native,
)


class ContextReq(enum.IntEnum):
    """Flags that the caller can specify what features they require.

    A list of features as bit flags that the caller can specify when creating the security context. These flags can
    be used on both Windows or Linux but are a no-op on Windows as it should always have the same features available.
    On Linux the features it can implement depend on a wide range of factors like the system libraries/headers that
    are installed, what GSSAPI implementation is present, and what Python libraries are available.

    This is a pretty advanced feature and is mostly a way to control the kerberos to ntlm fallback behaviour on Linux.

    These are the currently implemented feature flags:

    negotiate_kerberos:
        Will make sure that Kerberos is at least available to try for authentication when using the `negotiate`
        protocol. If Kerberos cannot be used due to the Python gssapi library not being installed then it will raise a
        :class:`spnego.exceptions.FeatureMissingError`. If Kerberos was available but it cannot get a credential or
        create a context then it will just fallback to NTLM auth. If you wish to only use Kerberos with no NTLM
        fallback, set `protocol='kerberos'` when creating the security context.

    session_key:
        Ensure that the authenticated context will be able to return the session key that was negotiated between the
        client and the server. Older versions of `gss-ntlmssp`_ do not expose the functions required to retrieve this
        info so when this feature flag is set then the NTLM fallback process will use `ntlm-auth`_ and not
        `gss-ntlmssp`_ if the latter is too old to retrieve the session key.

    wrapping_iov:
        The GSSAPI IOV methods are extensions to the Kerberos spec and not implemented or exposed on all platforms,
        macOS is a popular example. If the caller requires the wrap_iov and unwrap_iov methods this will ensure it
        fails fast before the auth has been set up. Unfortunately there is no fallback for this as if the headers
        aren't present for GSSAPI then we can't do anything to fix that. This won't fail if `negotiate` was used and
        NTLM was the chosen protocol as that happens post negotiation.

    wrapping_winrm:
        To created a wrapped WinRM message the IOV extensions are required when using Kerberos auth. Setting this flag
        will skip Kerberos when `protocol='negotiate'` if the IOV headers aren't present and just fallback to NTLM.

    .. _ntlm-auth:
        https://github.com/jborean93/ntlm-auth

    .. _gss-ntlmssp:
        https://github.com/gssapi/gss-ntlmssp
    """
    # GSSAPI|SSPI flags
    delegate = 0x00000001
    mutual_auth = 0x00000002
    replay_detect = 0x00000004
    sequence_detect = 0x00000008
    confidentiality = 0x00000010
    integrity = 0x00000020
    anonymous = 0x00000040
    delegate_policy = 0x00080000  # Only valid for GSSAPI, same as delegate on Windows.

    # pyspnego specific flags
    negotiate_kerberos = 0x100000000
    session_key = 0x200000000
    wrapping_iov = 0x400000000
    wrapping_winrm = 0x800000000


DEFAULT_REQ = ContextReq.integrity | ContextReq.confidentiality | ContextReq.sequence_detect | \
              ContextReq.replay_detect | ContextReq.mutual_auth


def split_username(username):  # type: (Optional[str]) -> Tuple[Optional[str], Optional[str]]
    """Splits a username and returns the domain component.

    Will split a username in the Netlogon form `DOMAIN\\username` and return the domain and user part as separate
    strings. If the user does not contain the `DOMAIN\\` prefix or is in the `UPN` form then then user stays the same
    and the domain is an empty string.

    Args:
        username: The username to split

    Returns:
        Tuple[Optional[str], Optional[str]]: The domain and username.
    """
    if username is None:
        return None, None

    if '\\' in username:
        domain, username = username.split('\\', 1)
    else:
        domain = ''

    return domain, username


def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass. This has been copied from six under the MIT license. """
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get('__slots__')
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop('__dict__', None)
        orig_vars.pop('__weakref__', None)
        if hasattr(cls, '__qualname__'):
            orig_vars['__qualname__'] = cls.__qualname__
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper


WrapResult = namedtuple('WrapResult', ['data', 'encrypted'])
"""Result of the `wrap()` function.

Attributes:
    data (bytes): The bytes of the wrapped data.
    encrypted (bool): Whether the data was encrypted (True) or not (False).
"""

IOVWrapResult = namedtuple('IOVWrapResult', ['buffers', 'encrypted'])
"""Result of the `wrap_iov()` function.

Attributes:
    buffers (Tuple[bytes, ...]): The wrapped bytes of the buffers passed into the function.
    encrypted (bool): Whether the buffer data was encrypted (True) or not (False).
"""

UnwrapResult = namedtuple('UnwrapResult', ['data', 'encrypted', 'qop'])
"""Result of the `unwrap()` function.

Attributes:
    data (bytes): The bytes of the unwrapped data.
    encrypted (bool): Whether the input data was encrypted (True) or not (False)
    qop (int): The Quality of Protection used for the encrypted data.
"""

IOVUnwrapResult = namedtuple('IOVUnwrapResult', ['buffers', 'encrypted', 'qop'])
"""Result of the `unwrap_iov()` function.

Attributes:
    buffers (Tuple[bytes, ...]): The unwrapped bytes of the buffers passed into the function.
    encrypted (bool): Whether the input buffers were encrypted (True) or not (False)
    qop (int): The Quality of Protection used for the encrypted buffers.
"""


@add_metaclass(ABCMeta)
class ContextProxy:
    """Base class for a authentication context.

    A base class the defined a common entry point for the various authentication context's that are used in this
    library. For a new context to be added it must implement the abstract functions in this class and translate the
    calls to what is required internally.

    Args:
        username: The username to authenticate with. Certain providers can use a cache if omitted.
        password: The password to authenticate with. Certain providers can use a cache if omitted.
        hostname: The principal part of the SPN. This is required for Kerberos auth to build the SPN.
        service: The service part of the SPN. This is required for Kerberos auth to build the SPN.
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
        delegate: Grants the acceptor the rights to act as a proxy and initiate further contexts on behalf of the
            initiator. This only works for Kerberos (or Kerberos through SPNEGO) authentication.
        mutual_auth: The initiator will also authenticate the acceptor. Only valid for an initiator.
        replay_detect: Detect replayed messaged from :meth:`wrap` and :meth:`sign`.
        sequence_detect: Detect messages received out of sequence.
        confidentiality: Whether the context can encrypt messages with :meth:`wrap`. Only valid for an initiator.
        integrity: Whether messages can be signed with :meth:`sign` or :meth:`wrap`.
        usage: The usage of the context, `initiate` for a client and `accept` for a server.
        protocol: The protocol to authenticate with, can be `ntlm`, `kerberos`, or `negotiate`. Not all providers
            support all three protocols as that is handled by :class:`SPNEGOContext`.

    Attributes:
        username (text_type): The username.
        password (text_type): The password for username.
        hostname (text_type): The principal part of the SPN.
        service (text_type): The service part of the SPN.
        channel_bindings (GssChannelBindings): The optional channel bindings object to bind to the auth.
        context_req (int): The context requirements flags as an int value specific to the context provider.
        context_attr (int): The context attributes of the completed authenticated context.
        usage (str): The usage of the context, `initiate` for a client and `accept` for a server.
        protocol (text_type): The protocol to set the context up with; `ntlm`, `kerberos`, or `negotiate`.
    """

    def __init__(self, username, password, hostname, service, channel_bindings, context_req, usage, protocol):
        # type: (Optional[text_type], Optional[text_type], Optional[text_type], Optional[text_type], Optional[GssChannelBindings], ContextReq, str, text_type) -> None  # noqa
        self.username = username
        self.password = password
        self.spn = self.create_spn(service or 'host', hostname or 'unspecified')
        self.channel_bindings = None
        if self.channel_bindings:
            self.convert_channel_bindings(channel_bindings)
        self.context_req = context_req
        self.context_attr = 0

        self.usage = usage.lower()
        if self.usage not in ['initiate', 'accept']:
            raise ValueError("Invalid usage '%s', must be initiate or accept" % self.usage)

        self.protocol = protocol.lower()
        if self.protocol not in [u'ntlm', u'kerberos', u'negotiate']:
            raise ValueError(to_native(u"Invalid protocol '%s', must be ntlm, kerberos, or negotiate" % self.protocol))

    @classmethod
    def available_protocols(cls, feature_flags=0):  # type: (Optional[int]) -> List[text_type, ...]
        """A list of protocols that the provider can offer.

        Returns a list of protocols the underlying provider can implement. Currently only kerberos, negotiate, or ntlm
        is understood. SSPI on Windows supports all 3, GSSAPI on Linux can support all 3 but depends on the environment
        setup. ntlm-auth only supports NTLM.

        Args:
            feature_flags: The feature flags of :class:`FeatureFlags` that state what features the client requires.

        Returns:
            List[text_type, ...]: The list of protocols that the context can use.
        """
        return [u'kerberos', u'negotiate', u'ntlm']

    @classmethod
    def iov_available(cls):  # type: () -> bool
        """Whether the context supports IOV wrapping and unwrapping.

        Will return a bool that states whether the context supports IOV wrapping or unwrapping. The NTLM protocol on
        Linux does not support IOV and some Linux gssapi implementations do not expose the extension headers for this
        function. This gives the caller a sane way to determine whether it can use :meth:`wrap_iov` or
        :meth:`unwrap_iov`.

        Returns:
            bool: Whether the context provider supports IOV wrapping and unwrapping (True) or not (False).
        """
        return True

    @property
    @abstractmethod
    def complete(self):  # type: () -> bool
        """Whether the context has completed the authentication process.

        Will return a bool that states whether the authentication process has completed successfully.

        Returns:
            bool: The authentication process is complete (True) or not (False).
        """
        pass

    @property
    @abstractmethod
    def negotiated_protocol(self):  # type: () -> text_type
        """The name of the negotiated protocol.

        Once the authentication process has compeleted this will return the name of the negotiated context that was
        used. For pure NTLM and Kerberos this will always be `ntlm` or `kerberos` respectively but for SPNEGO this can
        be either of those two.

        Returns:
            text_type: The protocol that was negotiated, can be `ntlm` or `kerberos`. This is a unicode string in
                Python 2 and a str string in Python 3.
        """
        pass

    @property
    @abstractmethod
    def session_key(self):  # type: () -> bytes
        """The derived session key.

        Once the authentication process is complete, this will return the derived session key. It is recommended to not
        use this key for your own encryption processes and is only exposed because some libraries use this key in their
        protocols.

        Returns:
            bytes: The derived session key from the authenticated context.
        """
        pass

    @abstractmethod
    def create_spn(self, service, principal):  # type: (text_type, text_type) -> text_type
        """Creates the SPN.

        Creates the SPN in the format required by the context. An SPN is required for Kerberos auth to work correctly.
        Typically on SSPI the SPN must be in the form 'HTTP/fqdn' whereas GSSAPI expected 'http@fqdn'.

        Args:
            service: The service part of the SPN.
            principal: The hostname or principal part of the SPN.

        Returns:
            text_type: The SPN in the format required by the context provider.
        """
        pass

    @abstractmethod
    def step(self, in_token=None):  # type: (Optional[bytes]) -> Optional[bytes]
        """Performs a negotiation step.

        This method performs a negotiation step and processes/generates a token. This token should be then sent to the
        counterpart context to continue the authentication process.

        This should not be called once :meth:`complete` is True as the security context is complete.

        For the initiator this is equivalent to `gss_init_sec_context`_ for GSSAPI and `InitializeSecurityContext`_ for
        SSPI.

        For the acceptor this is equivalent to `gss_accept_sec_context`_ for GSSAPI and `AcceptSecurityContext`_ for
        SSPI.

        Args:
            in_token: The input token to process (or None to process no input token).

        Returns:
            Optional[bytes]: The output token (or None if no output token is generated.

        .. _gss_init_sec_context:
            https://tools.ietf.org/html/rfc2744.html#section-5.19

        .. _InitializeSecurityContext:
            https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw

        .. _gss_accept_sec_context:
            https://tools.ietf.org/html/rfc2744.html#section-5.1

        .. _AcceptSecurityContext:
            https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acceptsecuritycontext
        """
        pass

    @abstractmethod
    def wrap(self, data, encrypt=True, qop=None):  # type: (bytes, bool, Optional[int]) -> WrapResult
        """Wrap a message, optionally with encryption.

        This wraps a message, signing it and optionally encrypting it. The :meth:`unwrap` will unwrap a message.

        This is the equivalent to `gss_wrap`_ for GSSAPI and `EncryptMessage`_ for SSPI.

        The SSPI function's `EncryptMessage`_ is called with the following buffers::

            SecBufferDesc(SECBUFFER_VERSION, [
                SecBuffer(SECBUFFER_TOKEN, sizes.cbSecurityTrailer, b""),
                SecBuffer(SECBUFFER_DATA, len(data), data),
                SecBuffer(SECBUFFER_PADDING, sizes.cbBlockSize, b""),
            ])

        Args:
            data: The data to wrap.
            encrypt: Whether to encrypt the data (True) or just wrap it with a MIC (False).
            qop: The desired Quality of Protection (or None to use the default).

        Returns:
            WrapResult: The wrapped result which contains the wrapped message and whether it was encrypted or not.

        .. _gss_wrap:
            https://tools.ietf.org/html/rfc2744.html#section-5.33

        .. _EncryptMessage:
            https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general
        """
        pass

    @abstractmethod
    def wrap_iov(self, iov, encrypt=True, qop=None):
        # type: (List[IOVBuffer, ...], bool, Optional[int]) -> IOVWrapResult
        """Wrap/Encrypt an IOV buffer.

        This method wraps/encrypts an IOV buffer. The IOV buffers control how the data is to be processed. Because
        IOV wrapping is an extension to GSSAPI and not implemented for NTLM on Linux, this method may not always be
        available to the caller. Check the :meth:`iov_available` property.

        This is the equivalent to `gss_wrap_iov`_ for GSSAPI and `EncryptMessage`_ for SSPI.

        Args:
            iov: A list of :class:`spnego.iov.IOVBuffer` buffers to wrap.
            encrypt: Whether to encrypt the message (True) or just wrap it with a MIC (False).
            qop: The desired Quality of Protection (or None to use the default).

        Returns:
            IOVWrapResult: The wrapped result which contains the wrapped IOVBuffer bytes and whether it was encrypted
                or not.

        .. _gss_wrap_iov:
            http://k5wiki.kerberos.org/wiki/Projects/GSSAPI_DCE

        .. _EncryptMessage:
            https://docs.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--general
        """
        pass

    @abstractmethod
    def unwrap(self, data):  # type: (bytes) -> UnwrapResult
        """Unwrap a message.

        This unwraps a message created by :meth:`wrap`.

        This is the equivalent to `gss_unwrap`_ for GSSAPI and `DecryptMessage`_ for SSPI.

        The SSPI function's `DecryptMessage`_ is called with the following buffers::

            SecBufferDesc(SECBUFFER_VERSION, [
                SecBuffer(SECBUFFER_STREAM, len(data), data),
                SecBuffer(SECBUFFER_DATA, 0, b""),
            ])

        Args:
            data: The data to unwrap.

        Returns:
            UnwrapResult: The unwrapped message, whether it was encrypted, and the QoP used.

        .. _gss_unwrap:
            https://tools.ietf.org/html/rfc2744.html#section-5.31

        .. _DecryptMessage:
            https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
        """
        pass

    @abstractmethod
    def unwrap_iov(self, iov):  # type: (List[IOVBuffer, ...]) -> IOVUnwrapResult
        """Unwrap/Decrypt an IOV buffer.

        This method unwraps/decrypts an IOV buffer. The IOV buffers control how the data is to be processed. Because
        IOV wrapping is an extension to GSSAPI and not implemented for NTLM on Linux, this method may not always be
        available to the caller. Check the :meth:`iov_available` property.

        This is the equivalent to `gss_unwrap_iov`_ for GSSAPI and `DecryptMessage`_ for SSPI.

        Args:
            iov: A list of :class:`spnego.iov.IOVBuffer` buffers to unwrap.

        Returns:
            IOVUnwrapResult: The unwrapped buffer bytes, whether it was encrypted, and the QoP used.

        .. _gss_unwrap_iov:
            http://k5wiki.kerberos.org/wiki/Projects/GSSAPI_DCE

        .. _DecryptMessage:
            https://docs.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general
        """
        pass

    @abstractmethod
    def sign(self, data, qop=None):  # type: (bytes, Optional[int]) -> bytes
        """Generates a signature/MIC for a message.

        This method generates a MIC for the given data. This is unlike wrap which bundles the MIC and the message
        together. The :meth:`verify` method can be used to verify a MIC.

        This is the equivalent to `gss_get_mic`_ for GSSAPI and `MakeSignature`_ for SSPI.

        Args:
            data: The data to generate the MIC for.
            qop: The desired Quality of Protection (or None to use the default).

        Returns:
            bytes: The MIC for the data requested.

        .. _gss_get_mic:
            https://tools.ietf.org/html/rfc2744.html#section-5.15

        .. _MakeSignature:
            https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-makesignature
        """
        pass

    @abstractmethod
    def verify(self, data, mic):  # type: (bytes, bytes) -> int
        """Verify the signature/MIC for a message.

        Will verify that the given MIC matches the given data. If the MIC does not match the given data, an exception
        will be raised. The :meth:`sign` method can be used to sign data.

        This is the equivalent to `gss_verify_mic`_ for GSSAPI and `VerifySignature`_ for SSPI.

        Args:
            data: The data to verify against the MIC.
            mic: The MIC to verify against the data.

        Returns:
            int: The QoP (Quality of Protection) used.

        .. _gss_verify_mic:
            https://tools.ietf.org/html/rfc2744.html#section-5.32

        .. _VerifySignature:
            https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-verifysignature
        """
        pass

    @abstractmethod
    def convert_channel_bindings(self, bindings):  # type: (Optional[GssChannelBindings]) -> any
        """Convert a GssChannelBindings object to a provider specific value.

        Converts the common GssChannelBindings object to the provider specific value that it can use when stepping
        through the authentication token.

        Args:
            bindings: The GssChannelBindings object to convert.

        Returns:
            Optional[any]: The provider specific value or None if no bindings where specified.
        """
        pass

    # Non-SSPI only functions when we create our own SPNEGO tokens with NTLM as the negotiated mech.

    @property
    def requires_mech_list_mic(self):  # type: () -> bool
        """Determine if the SPNEGO mechListMIC is required for the sec context.

        When Microsoft hosts deal with NTLM through SPNEGO it always wants the mechListMIC to be present when the NTLM
        authentication message contains a MIC. This goes against RFC 4178 as a mechListMIC shouldn't be required if
        NTLM was the preferred mech from the initiator but we can't do anything about that now. Because we exclusively
        use SSPI on Windows hosts, which does all the work for us, this function only matter for Linux hosts when this
        library manually creates the SPNEGO token.

        The function performs 2 operations. When called before the NTLM authentication message has been created it
        tells the gss-ntlmssp mech that it's ok to generate the MIC. When the authentication message has been created
        it returns a bool stating whether the MIC was present in the auth message and subsequently whether we need to
        include the mechListMIC in the SPNEGO token.

        See `mech_required_mechlistMIC in MIT KRB5`_ for more information about how MIT KRB5 deals with this.

        Returns:
            bool: Whether the SPNEGO mechListMIC needs to be generated or not.

        .. _mech_requires_mechlistMIC:
            https://github.com/krb5/krb5/blob/b2fe66fed560ae28917a4acae6f6c0f020156353/src/lib/gssapi/spnego/spnego_mech.c#L493
        """
        return False

    def reset_ntlm_crypto_state(self, outgoing=True):  # type: (bool) -> None
        """Reset the NTLM crypto handles after signing/verifying the SPNEGO mechListMIC.

        `MS-SPNG`_ documents that after signing or verifying the mechListMIC, the RC4 key state needs to be the same
        for the mechListMIC and for the first message signed/sealed by the application. Because we use SSPI on Windows
        hosts which does all the work for us this function only matters for Linux hosts.

        Args:
            outgoing: Whether to reset the outgoing or incoming RC4 key state.

        .. _MS-SPNG:
            https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/b87587b3-9d72-4027-8131-b76b5368115f
        """
        pass

    def _flag_is_set(self, name):
        """ Check if a context attribute flag is set from a common name. """
        flag_val = self.get_context_attribute_value(name)
        return self.context_attr & flag_val == flag_val
