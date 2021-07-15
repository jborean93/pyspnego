# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from spnego._context import (
    ContextProxy,
    ContextReq,
)

from spnego.channel_bindings import (
    GssChannelBindings,
)

from spnego.exceptions import (
    NegotiateOptions,
)

from spnego.gss import (
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


def _new_context(
    username: typing.Optional[str],
    password: typing.Optional[str],
    hostname: str,
    service: str,
    channel_bindings: typing.Optional[GssChannelBindings],
    context_req: ContextReq,
    protocol: str,
    options: NegotiateOptions,
    usage: str,
) -> ContextProxy:
    proto = protocol.lower()

    # Unless otherwise specified, we always favour the platform implementations (SSPI/GSSAPI) if they are available.
    # Otherwise fallback to the Python implementations (NegotiateProxy/NTLMProxy).
    use_flags = (NegotiateOptions.use_sspi | NegotiateOptions.use_gssapi | NegotiateOptions.use_negotiate |
                 NegotiateOptions.use_ntlm)
    use_specified = options & use_flags != 0

    if options & NegotiateOptions.use_sspi or (not use_specified and
                                               proto in SSPIProxy.available_protocols(options=options)):
        proxy = SSPIProxy

    elif options & NegotiateOptions.use_gssapi or (not use_specified and (proto == 'kerberos' or
                                                   proto in GSSAPIProxy.available_protocols(options=options))):
        proxy = GSSAPIProxy

    elif options & NegotiateOptions.use_negotiate or (not use_specified and proto == 'negotiate'):
        # If GSSAPI does not offer full negotiate support, use our own wrapper.
        proxy = NegotiateProxy

    elif options & NegotiateOptions.use_ntlm or (not use_specified and proto == 'ntlm'):
        # Finally if GSSAPI does not support ntlm, use our own wrapper.
        proxy = NTLMProxy

    else:
        raise ValueError("Invalid protocol specified '%s', must be kerberos, negotiate, or ntlm" % protocol)

    return proxy(username, password, hostname, service, channel_bindings, context_req, usage, proto, options)


def client(
    username: typing.Optional[str] = None,
    password: typing.Optional[str] = None,
    hostname: str = 'unspecified',
    service: str = 'host',
    channel_bindings: typing.Optional[GssChannelBindings] = None,
    context_req: ContextReq = ContextReq.default,
    protocol: str = 'negotiate',
    options: NegotiateOptions = NegotiateOptions.none,
) -> ContextProxy:
    """Create a client context to be used for authentication.

    Args:
        username: The username to authenticate with. Certain providers can use a cache if omitted.
        password: The password to authenticate with. Certain providers can use a cache if omitted.
        hostname: The principal part of the SPN. This is required for Kerberos auth to build the SPN.
        service: The service part of the SPN. This is required for Kerberos auth to build the SPN.
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
        context_req: The :class:`spnego.ContextReq` flags to use when setting up the context.
        protocol: The protocol to authenticate with, can be `ntlm`, `kerberos`, or `negotiate`. Not all providers
            support all three protocols as that is handled by :class:`SPNEGOContext`.
        options: The :class:`spnego.NegotiateOptions` that define pyspnego specific options to control the negotiation.

    Returns:
        ContextProxy: The context proxy for a client.
    """
    return _new_context(username, password, hostname, service, channel_bindings, context_req, protocol, options,
                        'initiate')


def server(
    hostname: str = 'unspecified',
    service: str = 'host',
    channel_bindings: typing.Optional[GssChannelBindings] = None,
    context_req: ContextReq = ContextReq.default,
    protocol: str = 'negotiate',
    options: NegotiateOptions = NegotiateOptions.none,
) -> ContextProxy:
    """Create a server context to be used for authentication.

    Args:
        hostname: The principal part of the SPN. This is required for Kerberos auth to build the SPN.
        service: The service part of the SPN. This is required for Kerberos auth to build the SPN.
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
        context_req: The :class:`spnego.ContextReq` flags to use when setting up the context.
        protocol: The protocol to authenticate with, can be `ntlm`, `kerberos`, or `negotiate`. Not all providers
            support all three protocols as that is handled by :class:`SPNEGOContext`.
        options: The :class:`spnego.NegotiateOptions` that define pyspnego specific options to control the negotiation.

    Returns:
        ContextProxy: The context proxy for a client.
    """
    return _new_context(None, None, hostname, service, channel_bindings, context_req, protocol, options,
                        'accept')
