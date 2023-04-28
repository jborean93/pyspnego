# -*- coding: utf-8 -*-
# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import socket
import sys

import pytest

import spnego
import spnego._credssp
import spnego._gss
import spnego._sspi
import spnego.channel_bindings
import spnego.iov
from spnego.exceptions import NoContextError


def _kerb_exchange(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
) -> None:
    tok1 = client.step()
    assert tok1
    assert not client.complete
    assert not server.complete

    tok2 = server.step(tok1)
    assert tok2
    assert not client.complete
    assert not server.complete

    if client.protocol == "negotiate":
        tok3 = client.step(tok2)
        assert tok3
        assert not client.complete
        assert not server.complete

        tok4 = server.step(tok3)
        assert tok4
        assert not client.complete
        assert server.complete

        tok5 = client.step(tok4)
        assert not tok5
        assert client.complete
        assert server.complete

    else:
        tok3 = client.step(tok2)
        assert tok3
        assert client.complete
        assert not server.complete

        tok4 = server.step(tok3)
        assert not tok4
        assert client.complete
        assert server.complete


def _ntlm_exchange(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
) -> None:
    negotiate = client.step()
    assert negotiate
    assert not client.complete
    assert not server.complete

    challenge = server.step(negotiate)
    assert challenge
    assert not client.complete
    assert not server.complete

    authentication = client.step(challenge)
    assert authentication

    # If it's being wrapped by SPNEGO then an extra msg is expected
    if authentication.startswith(b"NTLMSSP\x00"):
        assert client.complete
        assert not server.complete

        final = server.step(authentication)
        assert not final
        assert client.complete
        assert server.complete

    else:
        assert not client.complete
        assert not server.complete

        mech_list = server.step(authentication)
        assert mech_list
        assert not client.complete
        assert server.complete

        final = client.step(mech_list)
        assert not final
        assert client.complete
        assert server.complete


def _message_test(
    client: spnego.ContextProxy,
    server: spnego.ContextProxy,
    sign_header: bool = True,
) -> None:
    sign_type = spnego.iov.BufferType.sign_only if sign_header else spnego.iov.BufferType.data_readonly

    wrap1 = client.wrap_iov(
        [
            (sign_type, b"header"),
            b"data",
            (sign_type, b"sec_trailer"),
            spnego.iov.BufferType.header,
        ]
    )
    assert wrap1.buffers[1].data != b"data"

    unwrap1 = server.unwrap_iov(wrap1.buffers)
    assert unwrap1.buffers[1].data == b"data"

    wrap2 = server.wrap_iov(
        [
            (sign_type, b"header"),
            b"data",
            (sign_type, b"sec_trailer"),
            spnego.iov.BufferType.header,
        ]
    )
    assert wrap2.buffers[1].data != b"data"

    unwrap2 = client.unwrap_iov(wrap2.buffers)
    assert unwrap2.buffers[1].data == b"data"


@pytest.mark.parametrize("protocol", ["negotiate", "kerberos"])
def test_kerberos(protocol, kerb_cred):
    if sys.platform == "darwin":
        pytest.skip("Environment problem with GSS.Framework - skip")

    c = spnego.client(
        kerb_cred.user_princ,
        None,
        protocol=protocol,
        hostname=socket.getfqdn(),
        context_req=spnego.ContextReq.default | spnego.ContextReq.dce_style,
    )
    s = spnego.server(
        protocol=protocol,
        context_req=spnego.ContextReq.default | spnego.ContextReq.dce_style,
    )

    expected_no_context = "Cannot get message sizes until context has been established"
    with pytest.raises(NoContextError, match=expected_no_context):
        c.query_message_sizes()
    with pytest.raises(NoContextError, match=expected_no_context):
        s.query_message_sizes()

    _kerb_exchange(c, s)

    c_sizes = c.query_message_sizes()
    assert isinstance(c_sizes.header, int)

    s_sizes = s.query_message_sizes()
    assert isinstance(s_sizes.header, int)

    _message_test(c, s, sign_header=False)
    _message_test(c, s, sign_header=True)


@pytest.mark.parametrize("protocol", ["negotiate", "ntlm"])
def test_ntlm(protocol, ntlm_cred):
    c = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        protocol=protocol,
        hostname=socket.getfqdn(),
        context_req=spnego.ContextReq.default | spnego.ContextReq.dce_style,
    )
    s = spnego.server(
        protocol=protocol,
        context_req=spnego.ContextReq.default | spnego.ContextReq.dce_style,
        options=spnego.NegotiateOptions.use_negotiate,
    )

    expected_no_context = "Cannot get message sizes until context has been established"
    with pytest.raises(NoContextError, match=expected_no_context):
        c.query_message_sizes()
    with pytest.raises(NoContextError, match=expected_no_context):
        s.query_message_sizes()

    _ntlm_exchange(c, s)

    c_sizes = c.query_message_sizes()
    assert c_sizes.header == 16

    s_sizes = s.query_message_sizes()
    assert s_sizes.header == 16

    _message_test(c, s, sign_header=False)
    _message_test(c, s, sign_header=True)
