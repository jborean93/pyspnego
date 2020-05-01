# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from abc import (
    ABCMeta,
    abstractmethod,
)

from spnego.iov import (
    BufferType,
)


class FeatureFlags:
    """
    A list of features that the caller requires. This can control what protocol='negotiate' will actually negotiate
    as on Linux not all these features will necessarily be available. On Windows these feature flags are effectively
    no-op as it always supports them all.

    This is a pretty advanced feature and is mostly a way to control the kerberos to ntlm fallback on GSSAPI as not all
    callers need all the features exposed by this library.

    These are the currently implemented feature flags:

    NEGO_KERBEROS:
        GSSAPI will make sure that Kerberos is at least available to try for authentication when using the 'negotiate'
        protocol. If Kerberos cannot be used due to the Python gssapi library not being installed then it will raise a
        FeatureMissingError. If Kerberos was available but it cannot get a credential or create a context then it will
        just fallback to NTLM auth. If you wish to only use Kerberos with NTLM fallback, set protocol='kerberos'.

    SESSION_KEY:
        Ensure that the authenticated context will be able to return the session key that was negotiated between the
        client and the server. Older versions of gss-ntlmssp do not expose the functions required to retrieve this info
        so when this feature flag is set then the pyspnego NTLM fallback will utilise the ntlm-auth Python library for
        NTLM authentication. TODO: check that Heimdal implements gss_inquire_sec_context_by_oid.

    WRAPPING_IOV:
        The GSSAPI IOV methods are extensions to the Kerberos spec and not implemented or exposed on all platforms,
        macOS is a popular example. If the caller requires the wrap_iov and unwrap_iov methods this will ensure it
        fails fast before the auth has been set up. Unfortunately there is no fallback for this as if the headers
        aren't present for GSSAPI then we can't do anything to fix that.

    WRAPPING_WINRM:
        To created a wrapped WinRM message the IOV extensions are required when using Kerberos auth. Setting this flag
        will skip Kerberos when protocol='negotiate' if the IOV headers aren't present and just fallback to NTLM.
    """
    NEGO_KERBEROS = 0x00000001
    SESSION_KEY = 0x00000002
    WRAPPING_IOV = 0x00000004
    WRAPPING_WINRM = 0x00000008


def split_username(username):
    if username is None:
        return None, None

    if '\\' in username:
        return username.split('\\', 1)
    else:
        return '', username


def requires_context(method):
    def wrapped(self, *args, **kwargs):
        if not self.complete:
            raise RuntimeError("Function requires a set up authentication context.")

        return method(self, *args, **kwargs)
    return wrapped


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


@add_metaclass(ABCMeta)
class SecurityContextBase:

    _CONTEXT_FLAG_MAP = {}

    def __init__(self, username, password, hostname, service, channel_bindings, delegate, mutual_auth, replay_detect,
                 sequence_detect, confidentiality, integrity, protocol, is_client):
        """
        Base class for a security context. Various parameters may or may not be used by each implementing class.

        :param username: The username to authenticate with.
        :param password: The password for the user.
        :param hostname: The target hostname, used as part of building the SPN if required.
        :param service: The target service class, used as part of building the SPN if required.
        :param channel_bindings: An optional channel_binding.GssChannelBindings object.
        :param delegate: Whether to apply the delegate flag to the security context.
        :param mutual_auth:
        :param replay_detect:
        :param sequence_detect:
        :param confidentiality: Whether confidentiality (encryption) is required.
        :param integrity:
        :param protocol: Enforce a particular protocol on the security context. Each security context implementer
            specify what protocols it supports.
        :param is_client:
        """
        self.username = username
        self.password = password
        self.hostname = hostname
        self.protocol = protocol
        self.service = service
        self._spn = self._create_spn(self.service or 'HOST', self.hostname or 'unspecified')
        self._is_client = is_client

        self.channel_bindings = channel_bindings
        if channel_bindings:
            self.channel_bindings = self._convert_channel_bindings(channel_bindings)

        # Validate that the implementing classes provide all the flags we require and convert it to the int
        # representation required by the context.
        input_context = {
            'delegate': delegate,
            'mutual_auth': mutual_auth,
            'replay_detect': replay_detect,
            'sequence_detect': sequence_detect,
            'confidentiality': confidentiality,
            'integrity': integrity,
        }
        required_flags = frozenset(input_context.keys())
        implemented_flags = frozenset(self._CONTEXT_FLAG_MAP.keys())
        missing_flags = required_flags.difference(implemented_flags)
        if missing_flags:
            raise RuntimeError("%s does not implement mapping for the required context flags: %s"
                               % (self.__class__.__name__, ", ".join(missing_flags)))

        self._context_req = 0
        self._context_attr = 0  # flags set once the context has been completed
        for flag_name, value in input_context.items():
            if value:
                self._context_req |= self._CONTEXT_FLAG_MAP[flag_name]

    # Public properties that should be implemented in the sub class.

    @property
    @abstractmethod
    def complete(self):
        """ Whether the authentication exchange has finished and the context is ready for wrapping/unwrapping."""
        pass

    @property
    @requires_context
    @abstractmethod
    def negotiated_protocol(self):
        """ The protocol that was used in the negotiation process, either 'kerberos' or 'ntlm'. """
        pass

    @property
    @requires_context
    @abstractmethod
    def session_key(self):
        """ Session key associated with the set up context. """
        pass

    # Public methods that should be implemented in the sub class.

    @abstractmethod
    def step(self, in_token=None):
        """ A generator that yields authentication tokens and processes input tokens from the server. """
        pass

    @requires_context
    @abstractmethod
    def wrap(self, data, confidential=True):
        """ Wraps the data similar to EncryptMessage() in SSPI. """
        pass

    @requires_context
    @abstractmethod
    def wrap_iov(self, iov, confidential=True):
        """ Wraps the data similar to EncryptMessage() in SSPI but with fine grain control over the input buffers. """
        pass

    @requires_context
    def wrap_winrm(self, data, confidential=True):
        """ Wraps the data for use with WinRM. """
        return self.wrap_iov([
            BufferType.header,
            data,
            BufferType.padding,
        ], confidential=confidential)

    @requires_context
    @abstractmethod
    def unwrap(self, data):
        """ Unwraps the data similar to DecryptMessage() in SSPI. """
        pass

    @requires_context
    @abstractmethod
    def unwrap_iov(self, iov):
        """ Wraps the data similar to DecryptMessage() in SSPI but with fine grain control over the input buffers. """
        pass

    @requires_context
    def unwrap_winrm(self, header, data):
        """ Unwraps the data for use with WinRM. """
        return self.unwrap_iov([
            (BufferType.header, header),
            data,
            BufferType.data,
        ])[1]

    # Internal abstract methods that should be implemented in the sub class.

    @abstractmethod
    def _iov_buffer(self, buffer_type, data):
        """ Create a provider specific IOVBuffer that is used to build the IOV collection for wrapping/unwrapping. """
        pass

    @abstractmethod
    def _create_spn(self, service, principal):
        pass

    # Public properties that don't need to be implemented in sub classes.

    @property
    @requires_context
    def context_attributes(self):
        return self._context_attr

    @property
    @requires_context
    def confidentiality(self):
        return self._flag_is_set('confidentiality')

    @property
    @requires_context
    def delegate(self):
        return self._flag_is_set('delegate')

    @property
    @requires_context
    def integrity(self):
        return self._flag_is_set('integrity')

    @property
    @requires_context
    def mutual_auth(self):
        return self._flag_is_set('mutual_auth')

    @property
    @requires_context
    def replay_detect(self):
        return self._flag_is_set('replay_detect')

    @property
    @requires_context
    def sequence_detect(self):
        return self._flag_is_set('sequence_detect')

    # Internal methods not for public use.

    def _convert_channel_bindings(self, bindings):
        """
        Converts the generic channel_bindings.GssChannelBindings to the security context specific object. Defaults to
        just returning the byte string of the GSS Channel Bindings struct. Otherwise a security context class can
        return the structure it requires.

        :param bindings: The channel_bindings.GssChannelBindings to convert from.
        :returns: A security context specific object of the GSS Channel Bindings structure.
        """
        return bindings.get_data()

    def _build_iov(self, iov):
        buffers = []
        for i in iov:
            if isinstance(i, tuple):
                if len(i) != 2:
                    raise ValueError("IOV buffer tuple must contain 2 entries")

                buff_type, data = i
            elif isinstance(i, bytes):
                buff_type = 1
                data = i
            elif isinstance(i, int):
                buff_type = i
                data = None
            else:
                raise ValueError("IOV Buffer entry must be a tuple, bytes, or int")

            buffers.append(self._iov_buffer(buff_type, data))

        return buffers

    def _flag_is_set(self, name):
        flag_val = self._CONTEXT_FLAG_MAP[name]
        return self._context_attr & flag_val == flag_val
