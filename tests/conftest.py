# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import json
import os
import socket
import sys
import time
import typing
import warnings

import pytest

import spnego
import spnego.exceptions
from spnego._text import to_bytes, to_text

HAS_SSPI = True
try:
    import win32net
    import win32netcon
except ImportError:
    HAS_SSPI = False

KERBEROS_ENV_VAR = "PYSPNEGO_TEST_KERBEROS"


def get_data(name: str) -> bytes:
    with open(os.path.join(os.path.dirname(__file__), "data", name), mode="rb") as fd:
        return fd.read()


@pytest.fixture()
def ntlm_cred(tmpdir, monkeypatch):
    cleanup = None
    try:
        # Use unicode credentials to test out edge cases when dealing with non-ascii chars.
        clef = to_text(b"\xf0\x9d\x84\x9e")
        username = "ÜseӜ"
        password = "Pӓ$sw0r̈d"

        if sys.platform != "darwin":
            username += clef
            password += clef

        if HAS_SSPI:
            domain = to_text(socket.gethostname())

            buff = {
                "name": username,
                "password": password,
                "priv": win32netcon.USER_PRIV_USER,
                "comment": "Test account for pypsnego tests",
                "flags": win32netcon.UF_NORMAL_ACCOUNT,
            }
            try:
                win32net.NetUserAdd(None, 1, buff)
            except win32net.error as err:
                if err.winerror != 2224:  # Account already exists
                    raise

            def cleanup() -> None:
                win32net.NetUserDel(None, username)

        else:
            domain = "Dȫm̈Ąiᴞ"

        tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$.creds")
        with open(tmp_creds, mode="wb") as fd:
            fd.write(to_bytes("%s:%s:%s" % (domain, username, password)))

        monkeypatch.setenv("NTLM_USER_FILE", to_text(tmp_creds))

        yield "%s\\%s" % (domain, username), password

    finally:
        if cleanup is not None:
            cleanup()


@dataclasses.dataclass(frozen=True)
class KerberosRealm:
    """The Kerberos realm the tests authenticate against.

    The realm is served by the KDC that build_helpers/run-with-kdc.ps1 starts.
    It passes the details through the PYSPNEGO_TEST_KERBEROS environment
    variable as JSON, which the kerb_realm fixture reads.

    Attributes:
        realm: The name of the realm.
        hostname: The hostname of the service the clients authenticate to.
        service: The service class of the service's principal, like host.
        username: The user principal, in the UPN form user@REALM.
        password: The password of the user principal.
        client_keytab: Path to a keytab with the keys of the user principal.
        acceptor_username: The principal whose keys the service tickets are
            encrypted with, in the UPN form. The service principal is an alias
            of this account.
        acceptor_keytab: Path to a keytab with the keys of the acceptor
            principal and the service principal.
        ccache: The credential cache that holds a TGT for the user, None on
            Windows where SSPI has no credential cache.
        provider: The Kerberos provider of the platform, gssapi or sspi.
    """

    realm: str
    hostname: str
    service: str
    username: str
    password: str
    client_keytab: str
    acceptor_username: str
    acceptor_keytab: str
    ccache: typing.Optional[str]
    provider: str

    @property
    def expected_client_principal(self) -> str:
        """The name the server reports for the user once authenticated.

        The service's tickets have no PAC so a Windows acceptor can verify them
        without running as SYSTEM, in which case Windows names the client
        REALM\\user rather than by its principal name.
        """
        if self.provider == "sspi":
            user = self.username.rsplit("@", 1)[0]
            return f"{self.realm}\\{user}"

        return self.username

    def client(
        self,
        username: typing.Union[str, spnego.Credential, typing.List[spnego.Credential], None] = None,
        password: typing.Optional[str] = None,
        *,
        protocol: str = "kerberos",
        **kwargs: typing.Any,
    ) -> spnego.ContextProxy:
        """Creates a client context that targets the realm's service.

        Any kwargs are passed to spnego.client. The hostname and service
        default to the realm's service when they are not set.
        """
        kwargs.setdefault("hostname", self.hostname)
        kwargs.setdefault("service", self.service)
        return spnego.client(username, password, protocol=protocol, **kwargs)

    def server(
        self,
        *,
        protocol: str = "kerberos",
        **kwargs: typing.Any,
    ) -> spnego.ContextProxy:
        """Creates a server context that accepts tickets for the realm's service.

        Any kwargs are passed to spnego.server. With GSSAPI the server uses
        the keytab set by KRB5_KTNAME unless credentials are given. SSPI has
        no default acceptor identity for the realm so the acceptor credential
        is used unless credentials are given.
        """
        if self.provider == "sspi":
            cred = spnego.KerberosKeytab(keytab=self.acceptor_keytab, principal=self.acceptor_username)
            kwargs.setdefault("credentials", cred)

        return spnego.server(protocol=protocol, **kwargs)


@pytest.fixture(scope="session")
def _kerb_realm_session() -> typing.Optional[KerberosRealm]:
    raw_realm = os.environ.get(KERBEROS_ENV_VAR)
    if not raw_realm:
        return None

    realm_info = json.loads(raw_realm)
    realm = KerberosRealm(
        realm=realm_info["realm"],
        hostname=realm_info["hostname"],
        service=realm_info["service"],
        username=realm_info["username"],
        password=realm_info["password"],
        client_keytab=realm_info["client_keytab"],
        acceptor_username=realm_info["acceptor_username"],
        acceptor_keytab=realm_info["acceptor_keytab"],
        ccache=realm_info.get("ccache"),
        provider="sspi" if sys.platform == "win32" else "gssapi",
    )
    if realm.provider == "sspi":
        _warm_up_sspi(realm)

    return realm


def _warm_up_sspi(realm: KerberosRealm, attempts: int = 5, delay: float = 2.0) -> None:
    """Authenticates once with SSPI before the tests use the realm.

    On a freshly started Windows CI runner the first SSPI Kerberos acceptor
    can fail to acquire its keytab credential with SEC_E_NO_CREDENTIALS, later
    ones succeed. The exchange is retried so the first test does not hit this,
    each failure is emitted as a warning so it shows in the test summary.
    """
    for attempt in range(1, attempts + 1):
        try:
            client = realm.client(realm.username)
            server = realm.server()
            server_token = server.step(client.step())
            client.step(server_token)
            return

        except spnego.exceptions.SpnegoError as e:
            warnings.warn(f"SSPI Kerberos warm up attempt {attempt}/{attempts} failed: {e}")
            if attempt == attempts:
                raise

            time.sleep(delay)


@pytest.fixture()
def kerb_realm(_kerb_realm_session: typing.Optional[KerberosRealm]) -> KerberosRealm:
    """The Kerberos realm to test against, skips the test if there is none."""
    if _kerb_realm_session is None:
        pytest.skip(
            f"Kerberos tests require {KERBEROS_ENV_VAR} to be set, run the tests through "
            "build_helpers/run-with-kdc.ps1 to start a KDC"
        )

    return _kerb_realm_session


@pytest.fixture()
def kerb_ccache(kerb_realm: KerberosRealm) -> str:
    """A credential cache with the TGT of the realm's user, GSSAPI only."""
    if not kerb_realm.ccache:
        pytest.skip(f"Kerberos provider {kerb_realm.provider} does not use a credential cache")

    return kerb_realm.ccache
