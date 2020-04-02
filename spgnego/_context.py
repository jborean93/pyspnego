# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


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


class _AuthContext:

    @property
    def complete(self):
        """ Whether the authentication exchange has finished and the context is ready for wrapping/unwrapping."""
        raise NotImplementedError()

    @property
    @requires_context
    def session_key(self):
        """ Session key associated with the set up context. """
        raise NotImplementedError()

    def step(self):
        """ A generator that yields authentication tokens and processes input tokens from the server. """
        raise NotImplementedError()

    @requires_context
    def wrap(self, data):
        """ Wraps the data similar to EncryptMessage() in SSPI. """
        raise NotImplementedError()

    @requires_context
    def unwrap(self, header, data):
        """ Unwraps the data similar to DecryptMessage() in SSPI. """
        raise NotImplementedError()