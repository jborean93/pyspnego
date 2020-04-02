# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import logging
import logging.config
import os

from spnego.ntlm import NTLM

GSSAPI = None
try:
    from spnego.gssapi import GSSAPI
except ImportError:
    pass

SSPI = None
try:
    from spnego.sspi import SSPI
except ImportError:
    pass

try:
    from logging import NullHandler
except ImportError:  # pragma: no cover
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass


def _setup_logging(l):
    log_path = os.environ.get('PYSPNEGO_LOG_CFG', None)

    if log_path is not None and os.path.exists(log_path):  # pragma: no cover
        # log log config from JSON file
        with open(log_path, 'rt') as f:
            config = json.load(f)

        logging.config.dictConfig(config)
    else:
        # no logging was provided
        l.addHandler(NullHandler())


logger = logging.getLogger(__name__)
_setup_logging(logger)


def initialize_security_context(username, password, hostname=None, service='HOST', delegate=False,
                                confidentiality=True, channel_bindings=None, provider='negotiate'):
    # FUTURE: See if we can pluginise each provider and add a method for someone to define their own.
    if provider not in ['negotiate', 'ntlm', 'kerberos']:
        raise ValueError("provider must be negotiate, ntlm, or kerberos")

    if provider == 'ntlm':
        return NTLM(username, password, channel_bindings=channel_bindings)

    return None
