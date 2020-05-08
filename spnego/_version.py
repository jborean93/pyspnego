# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

__version__ = '0.0.1.dev0'


from spnego._ntlm_raw.messages import (
    Version,
)


def get_ntlm_version():
    """ Generates an NTLM Version structure based on the pyspnego package version. """
    v = [v for v in __version__.split('.', 3) if v]
    v += [0] * (3 - len(v))

    return Version(major=int(v[0]), minor=int(v[1]), build=int(v[2]))
