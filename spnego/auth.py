# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from spnego.gssapi import (
    GSSAPIProxy,
)

from spnego.negotiate import (
    NegotiateProxy,
)

from spnego.ntlm import (
    NTLMProxy,
)

from spnego.sspi import (
    SSPIProxy,
)

from spnego._context import (
    ContextReq,
)


def _new_context(username, password, hostname, service, channel_bindings, context_req, protocol, usage):
    proto = protocol.lower()

    # Unless otherwise specified, we always favour the platform implementations (SSPI/GSSAPI) if they are available.
    # Otherwise fallback to the Python implementations (NegotiateProxy/NTLMProxy).
    use_flags = (ContextReq.use_sspi | ContextReq.use_gssapi | ContextReq.use_negotiate | ContextReq.use_ntlm)
    use_specified = context_req & use_flags != 0

    if context_req & ContextReq.use_sspi or (not use_specified and
                                             proto in SSPIProxy.available_protocols(context_req=context_req)):
        proxy = SSPIProxy

    elif context_req & ContextReq.use_gssapi or (not use_specified and (proto == 'kerberos' or
                                                 proto in GSSAPIProxy.available_protocols(context_req=context_req))):
        proxy = GSSAPIProxy

    elif context_req & ContextReq.use_negotiate or (not use_specified and proto == 'negotiate'):
        # If GSSAPI does not offer negotiate support, use our own wrapper.
        proxy = NegotiateProxy

    elif context_req & ContextReq.use_ntlm or (not use_specified and proto == 'ntlm'):
        # Finally if GSSAPI does not support ntlm, use our own wrapper.
        proxy = NTLMProxy

    else:
        raise ValueError("Invalid protocol specified '%s', must be kerberos, negotiate, or ntlm" % protocol)

    return proxy(username, password, hostname, service, channel_bindings, context_req, usage, proto)


def client(username, password, hostname='unspecified', service='host', channel_bindings=None,
           context_req=ContextReq.default, protocol='negotiate'):
    return _new_context(username, password, hostname, service, channel_bindings, context_req, protocol, 'initiate')


def server(username, password, hostname='unspecified', service='host', channel_bindings=None,
           context_req=ContextReq.default, protocol='negotiate'):
    return _new_context(username, password, hostname, service, channel_bindings, context_req, protocol, 'accept')
