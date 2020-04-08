# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from abc import (
    ABCMeta,
    abstractmethod,
)


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
class SecurityContext:

    def __init__(self, username, password, hostname, service, channel_bindings, delegate, confidentiality, protocol):
        """
        Base class for a security context. Various parameters may or may not be used by each implementing class.

        :param username: The username to authenticate with.
        :param password: The password for the user.
        :param hostname: The target hostname, used as part of building the SPN if required.
        :param service: The target service class, used as part of building the SPN if required.
        :param channel_bindings: An optional channel_binding.GssChannelBindings object.
        :param delegate: Whether to apply the delegate flag to the security context.
        :param confidentiality: Whether confidentiality (encryption) is required.
        :param protocol: Enforce a particular protocol on the security context. Each security context implementer
            specify what protocols it supports.
        """
        self.username = username
        self.password = password
        self.hostname = hostname
        self.service = service

        self.channel_bindings = channel_bindings
        if channel_bindings:
            self.channel_bindings = self.convert_channel_bindings(channel_bindings)

        self.delegate = delegate
        self.confidentiality = confidentiality

        supported_protocols = self.supported_protocols()
        self.protocol = protocol
        if protocol not in supported_protocols:
            raise ValueError("Specified protocol %s is not supported by this security context, valid protocols: %s"
                             % (protocol, ", ".join(supported_protocols)))

    @classmethod
    @abstractmethod
    def supported_protocols(cls):
        pass

    @property
    @abstractmethod
    def complete(self):
        """ Whether the authentication exchange has finished and the context is ready for wrapping/unwrapping."""
        pass

    @property
    @requires_context
    @abstractmethod
    def session_key(self):
        """ Session key associated with the set up context. """
        pass

    @abstractmethod
    def step(self):
        """ A generator that yields authentication tokens and processes input tokens from the server. """
        pass

    @requires_context
    @abstractmethod
    def wrap(self, data, confidential=True):
        """ Wraps the data similar to EncryptMessage() in SSPI. """
        pass

    @requires_context
    @abstractmethod
    def wrap_iov(self, *iov, confidential=True):
        """ Wraps the data similar to EncryptMessage() in SSPI but with fine grain control over the input buffers. """
        pass

    @requires_context
    @abstractmethod
    def unwrap(self, data):
        """ Unwraps the data similar to DecryptMessage() in SSPI. """
        pass

    @requires_context
    @abstractmethod
    def unwrap_iov(self, *iov):
        """ Wraps the data similar to DecryptMessage() in SSPI but with fine grain control over the input buffers. """
        pass

    @staticmethod
    def convert_channel_bindings(bindings):
        """
        Converts the generic channel_bindings.GssChannelBindings to the security context specific object. Defaults to
        just returning the byte string of the GSS Channel Bindings struct. Otherwise a security context class can
        return the structure it requires.

        :param bindings: The channel_bindings.GssChannelBindings to convert from.
        :returns: A security context specific object of the GSS Channel Bindings structure.
        """
        return bindings.get_data()
