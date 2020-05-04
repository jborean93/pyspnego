# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import logging
import logging.config
import os

from spnego.gssapi import GSSAPIProxy
from spnego.negotiate import NegotiateProxy
from spnego.ntlm import NTLMProxy

from spnego._context import DEFAULT_REQ, ContextReq

HAS_SSPI = True
try:
    from spnego.sspi import SSPIProxy
except ImportError:
    HAS_SSPI = False


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


def client(username, password, hostname='unspecified', service='host', channel_bindings=None, context_req=DEFAULT_REQ,
           protocol='negotiate'):

    if HAS_SSPI:
        return SSPIProxy(username, password, hostname, service, channel_bindings, context_req, protocol)

    protocol = protocol.lower()
    gssapi_protocols = GSSAPIProxy.available_protocols()
    if protocol in gssapi_protocols:
        return GSSAPIProxy(username, password, hostname, service, channel_bindings, context_req, 'initiate', protocol)
    elif protocol == 'kerberos':
        raise Exception("gssapi is not available")
    elif protocol == 'negotiate':
        return NegotiateProxy(username, password, hostname, service, channel_bindings, context_req, 'initiate',
                              protocol)
    elif protocol == 'ntlm':
        return NTLMProxy(username, password, channel_bindings, context_req)
    else:
        raise ValueError("Invalid protocol specified '%s', must be kerberos, negotiate, or ntlm" % protocol)


def server():
    raise NotImplementedError()
