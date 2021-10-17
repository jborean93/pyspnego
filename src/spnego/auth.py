# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from spnego._context import ContextProxy, ContextReq
from spnego._credssp import CredSSPProxy
from spnego._gss import GSSAPIProxy
from spnego._negotiate import NegotiateProxy
from spnego._ntlm import NTLMProxy
from spnego._ntlm_raw.crypto import is_ntlm_hash
from spnego._sspi import SSPIProxy
from spnego.channel_bindings import GssChannelBindings
from spnego.exceptions import NegotiateOptions


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
    **kwargs: typing.Any,
) -> ContextProxy:
    proto = protocol.lower()
    sspi_protocols = SSPIProxy.available_protocols(options=options)
    gssapi_protocols = GSSAPIProxy.available_protocols(options=options)

    # Unless otherwise specified, we always favour the platform implementations (SSPI/GSSAPI) if they are available.
    # Otherwise fallback to the Python implementations (NegotiateProxy/NTLMProxy).
    use_flags = (NegotiateOptions.use_sspi | NegotiateOptions.use_gssapi | NegotiateOptions.use_negotiate |
                 NegotiateOptions.use_ntlm)
    use_specified = options & use_flags != 0

    # When requesting a delegated context with explicit credentials we cannot rely on GSSAPI for Negotiate auth. There
    # is no way to explicitly request a forwardable Kerberos ticket for use with SPNEGO.
    forwardable = bool(context_req & ContextReq.delegate or context_req & ContextReq.delegate_policy)
    if username and password and forwardable and 'negotiate' in gssapi_protocols:
        gssapi_protocols.remove('negotiate')

    proxy: typing.Type[ContextProxy]

    # If the protocol is CredSSP then we can only use CredSSPProxy. The use_flags still control what underlying
    # Negotiate auth is used in the CredSSP authentication process.
    if proto == 'credssp':
        proxy = CredSSPProxy

    # If the procotol has been explicitly set to NTLM and an NTLM hash has been provided as the password, do not favour
    # the platform implementations. Instead, use the Python NTLMProxy implementation, since SSPI/GSSAPI so not allow
    # authentication using hashes.
    elif proto == 'ntlm' and password is not None and is_ntlm_hash(password):
        proxy = NTLMProxy

    elif options & NegotiateOptions.use_sspi or (not use_specified and proto in sspi_protocols):
        proxy = SSPIProxy

    elif options & NegotiateOptions.use_gssapi or (not use_specified and (proto == 'kerberos' or
                                                   proto in gssapi_protocols)):
        proxy = GSSAPIProxy

    elif options & NegotiateOptions.use_negotiate or (not use_specified and proto == 'negotiate'):
        # If GSSAPI does not offer full negotiate support, use our own wrapper.
        proxy = NegotiateProxy

    elif options & NegotiateOptions.use_ntlm or (not use_specified and proto == 'ntlm'):
        # Finally if GSSAPI does not support ntlm, use our own wrapper.
        proto = 'ntlm' if proto == 'negotiate' else proto
        proxy = NTLMProxy

    else:
        raise ValueError("Invalid protocol specified '%s', must be kerberos, negotiate, or ntlm" % protocol)

    return proxy(username, password, hostname, service, channel_bindings, context_req, usage, proto, options, **kwargs)


def client(
    username: typing.Optional[str] = None,
    password: typing.Optional[str] = None,
    hostname: str = 'unspecified',
    service: str = 'host',
    channel_bindings: typing.Optional[GssChannelBindings] = None,
    context_req: ContextReq = ContextReq.default,
    protocol: str = 'negotiate',
    options: NegotiateOptions = NegotiateOptions.none,
    **kwargs: typing.Any,
) -> ContextProxy:
    """Create a client context to be used for authentication.

    Args:
        username: The username to authenticate with. Certain providers can use a cache if omitted.
        password: The password to authenticate with. Certain providers can use a cache if omitted.
        hostname: The principal part of the SPN. This is required for Kerberos auth to build the SPN.
        service: The service part of the SPN. This is required for Kerberos auth to build the SPN.
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
        context_req: The :class:`spnego.ContextReq` flags to use when setting up the context.
        protocol: The protocol to authenticate with, can be `ntlm`, `kerberos`, `negotiate`, or `credssp`.
        options: The :class:`spnego.NegotiateOptions` that define pyspnego specific options to control the negotiation.
        kwargs: Optional arguments to pass through to the authentiction context.

    Returns:
        ContextProxy: The context proxy for a client.
    """
    return _new_context(username, password, hostname, service, channel_bindings, context_req, protocol, options,
                        'initiate', **kwargs)


def server(
    hostname: str = 'unspecified',
    service: str = 'host',
    channel_bindings: typing.Optional[GssChannelBindings] = None,
    context_req: ContextReq = ContextReq.default,
    protocol: str = 'negotiate',
    options: NegotiateOptions = NegotiateOptions.none,
    **kwargs: typing.Any,
) -> ContextProxy:
    """Create a server context to be used for authentication.

    Args:
        hostname: The principal part of the SPN. This is required for Kerberos auth to build the SPN.
        service: The service part of the SPN. This is required for Kerberos auth to build the SPN.
        channel_bindings: The optional :class:`spnego.channel_bindings.GssChannelBindings` for the context.
        context_req: The :class:`spnego.ContextReq` flags to use when setting up the context.
        protocol: The protocol to authenticate with, can be `ntlm`, `kerberos`, `negotiate`, or `credssp`.
        options: The :class:`spnego.NegotiateOptions` that define pyspnego specific options to control the negotiation.
        kwargs: Optional arguments to pass through to the authentiction context.

    Returns:
        ContextProxy: The context proxy for a client.
    """
    return _new_context(None, None, hostname, service, channel_bindings, context_req, protocol, options,
                        'accept', **kwargs)
