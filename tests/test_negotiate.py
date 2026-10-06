# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

import pytest

import spnego
import spnego._gss
from spnego._context import GSSMech
from spnego._negotiate import NegotiateProxy
from spnego._spnego import NegState, NegTokenInit, NegTokenResp
from spnego.exceptions import BadMechanismError, InvalidTokenError


def test_token_rejected(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    token_resp = NegTokenResp(neg_state=NegState.reject).pack()

    with pytest.raises(InvalidTokenError, match="Received SPNEGO rejection with no token error message"):
        c.step(token_resp)


def test_token_invalid_input(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    c.step()
    with pytest.raises(InvalidTokenError, match="Failed to unpack input token"):
        c.step(b"\x00")


def test_token_no_common_mechs(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)

    with pytest.raises(BadMechanismError, match="Unable to negotiate common mechanism"):
        c.step(NegTokenInit(mech_types=["1.2.3.4"]).pack())


def test_token_acceptor_first(ntlm_cred):
    c = spnego.client(ntlm_cred[0], ntlm_cred[1], options=spnego.NegotiateOptions.use_negotiate)
    s = spnego.server(options=spnego.NegotiateOptions.use_negotiate)

    assert getattr(c, "_mech_list", None) == []
    assert getattr(s, "_mech_list", None) == []

    token1 = s.step()
    assert isinstance(token1, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == []
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    negotiate = c.step(token1)
    assert isinstance(negotiate, bytes)
    assert not c.complete
    assert not s.complete
    assert getattr(c, "_mech_list", None) == [GSSMech.ntlm.value]
    assert GSSMech.ntlm.value in getattr(s, "_mech_list", [])

    challenge = s.step(negotiate)
    assert isinstance(challenge, bytes)
    assert not c.complete
    assert not s.complete

    authenticate = c.step(challenge)
    assert isinstance(authenticate, bytes)
    assert not c.complete
    assert not s.complete

    mech_list_mic = s.step(authenticate)
    assert isinstance(mech_list_mic, bytes)
    assert not c.complete
    assert s.complete

    final_token = c.step(mech_list_mic)
    assert final_token is None
    assert c.complete
    assert s.complete


@pytest.mark.skipif("ntlm" not in spnego._sspi.SSPIProxy.available_protocols(), reason="Requires SSPI library")
def test_iov_available_sspi():
    assert NegotiateProxy.iov_available()


@pytest.mark.skipif(not spnego._gss.HAS_GSSAPI, reason="Requires the gssapi library to be installed for testing")
def test_iov_available_gssapi():
    assert NegotiateProxy.iov_available() == spnego._gss.GSSAPIProxy.iov_available()


class FakeKerberosContext(spnego._context.ContextProxy):
    """A stand in for a Kerberos context that completes in one round trip without needing a KDC."""

    def __init__(self, usage: str = "initiate") -> None:
        super().__init__(
            [spnego.CredentialCache()],
            None,
            None,
            None,
            spnego.ContextReq.default,
            usage,
            "kerberos",
            spnego.NegotiateOptions.none,
        )
        self._complete = False
        self.tokens: typing.List[typing.Optional[bytes]] = []

    @classmethod
    def available_protocols(cls, options=None):
        return ["kerberos"]

    @property
    def client_principal(self):
        return None

    @property
    def complete(self):
        return self._complete

    @property
    def negotiated_protocol(self):
        return "kerberos"

    @property
    def session_key(self):
        return b"\x00" * 16

    def new_context(self):
        return FakeKerberosContext(self.usage)

    def query_message_sizes(self):
        raise NotImplementedError()

    def step(self, in_token=None, *, channel_bindings=None):
        self.tokens.append(in_token)
        if self.usage == "accept":
            self._complete = True
            return b"AP-REP"

        elif in_token:
            self._complete = True
            return None

        else:
            return b"AP-REQ"

    def wrap(self, data, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_iov(self, iov, encrypt=True, qop=None):
        raise NotImplementedError()

    def wrap_winrm(self, data):
        raise NotImplementedError()

    def unwrap(self, data):
        raise NotImplementedError()

    def unwrap_iov(self, iov):
        raise NotImplementedError()

    def unwrap_winrm(self, header, data):
        raise NotImplementedError()

    def sign(self, data, qop=None):
        return b"MIC" + data

    def verify(self, data, mic):
        assert mic == b"MIC" + data
        return 0

    @property
    def _context_attr_map(self):
        return []


@pytest.fixture()
def kerberos_preferred(monkeypatch):
    """Make the Negotiate proxy prefer Kerberos regardless of what the host supports."""
    monkeypatch.setattr(
        NegotiateProxy,
        "available_protocols",
        classmethod(lambda cls, options=None: ["kerberos", "ntlm", "negotiate"]),
    )


@pytest.mark.parametrize(
    "mech_types, expected_mech",
    [
        # Windows lists the MS Kerberos OID first and rejects a reply that does not echo it.
        (
            [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.negoex.value, GSSMech.ntlm.value],
            GSSMech._ms_kerberos.value,
        ),
        ([GSSMech.kerberos.value, GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech.kerberos.value, GSSMech.ntlm.value], GSSMech.kerberos.value),
        ([GSSMech._ms_kerberos.value, GSSMech.ntlm.value], GSSMech._ms_kerberos.value),
    ],
)
def test_acceptor_echoes_offered_kerberos_oid(mech_types, expected_mech, kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    init = NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)

    assert isinstance(resp, NegTokenResp)
    assert resp.supported_mech == expected_mech
    assert resp.neg_state == NegState.accept_complete
    assert resp.response_token == b"AP-REP"
    assert resp.mech_list_mic is None
    assert s.complete
    assert s.negotiated_protocol == "kerberos"


def test_acceptor_verifies_mic_after_ms_kerberos(kerberos_preferred):
    s = NegotiateProxy(
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("accept")},
    )

    mech_types = [GSSMech._ms_kerberos.value, GSSMech.kerberos.value, GSSMech.ntlm.value]
    s.step(NegTokenInit(mech_types=mech_types, mech_token=b"AP-REQ").pack())
    assert s.complete

    # Windows still sends its mechListMIC after accept-completed, it must verify against the list it sent.
    mic = b"MIC" + spnego._spnego.pack_mech_type_list(mech_types)
    assert s.step(NegTokenResp(mech_list_mic=mic).pack()) is None
    assert s.complete


def test_acceptor_creates_mech_contexts_with_credentials(monkeypatch, kerberos_preferred):
    real_server = spnego.server
    calls = []

    def fake_server(**kwargs):
        calls.append(kwargs)
        if kwargs["protocol"] == "kerberos":
            return FakeKerberosContext("accept")

        return real_server(**kwargs)

    monkeypatch.setattr(spnego, "server", fake_server)

    cred = spnego.Password(username="svc-winrm@PSWSMAN.TEST", password="pass")
    s = NegotiateProxy(
        cred,
        hostname="winrm.pswsman.test",
        service="HTTP",
        usage="accept",
        options=spnego.NegotiateOptions.use_negotiate,
    )

    # Only the MS Kerberos OID is offered, the acceptor must still treat that as Kerberos.
    init = NegTokenInit(mech_types=[GSSMech._ms_kerberos.value, GSSMech.ntlm.value], mech_token=b"AP-REQ").pack()
    out_token = s.step(init)
    assert out_token
    resp = spnego._spnego.unpack_token(out_token)
    assert isinstance(resp, NegTokenResp)

    kerberos_calls = [c for c in calls if c["protocol"] == "kerberos"]
    assert len(kerberos_calls) == 1
    assert kerberos_calls[0]["credentials"] == [cred]
    assert kerberos_calls[0]["hostname"] == "winrm.pswsman.test"
    assert kerberos_calls[0]["service"] == "HTTP"

    assert resp.supported_mech == GSSMech._ms_kerberos.value
    assert resp.neg_state == NegState.accept_complete
    assert s.complete


@pytest.mark.parametrize("supported_mech", [GSSMech._ms_kerberos.value, GSSMech._kerberos_draft.value])
def test_initiator_accepts_kerberos_alias_supported_mech(supported_mech):
    c = NegotiateProxy(
        usage="initiate",
        options=spnego.NegotiateOptions.use_negotiate,
        _negotiate_contexts={GSSMech.kerberos: FakeKerberosContext("initiate")},
    )

    out_token = c.step()
    assert out_token
    init = spnego._spnego.unpack_token(out_token)
    assert isinstance(init, NegTokenInit)
    assert init.mech_types == [GSSMech.kerberos.value]
    assert init.mech_token == b"AP-REQ"

    resp = NegTokenResp(
        neg_state=NegState.accept_complete,
        supported_mech=supported_mech,
        response_token=b"AP-REP",
    ).pack()
    assert c.step(resp) is None
    assert c.complete
    assert c.negotiated_protocol == "kerberos"
