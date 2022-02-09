# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import locale
import os
import socket

import pytest

from spnego._text import to_bytes, to_text

HAS_K5TEST = True
try:
    from k5test.realm import K5Realm
except Exception:  # Can fail with more than ImportError on some systems
    HAS_K5TEST = False

HAS_SSPI = True
try:
    import win32net
    import win32netcon
except ImportError:
    HAS_SSPI = False


def get_data(name: str) -> bytes:
    with open(os.path.join(os.path.dirname(__file__), "data", name), mode="rb") as fd:
        return fd.read()


@pytest.fixture()
def ntlm_cred(tmpdir, monkeypatch):
    cleanup = None
    try:
        # Use unicode credentials to test out edge cases when dealing with non-ascii chars.
        username = "ÜseӜ"
        password = "Pӓ$sw0r̈d"

        if HAS_SSPI:
            domain = to_text(socket.gethostname())

            # Can only test this out with Windows due to issue with gss-ntlmssp when dealing with surrogate pairs.
            # https://github.com/gssapi/gss-ntlmssp/issues/20
            clef = to_text(b"\xF0\x9D\x84\x9E")
            username += clef
            password += clef

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

            # gss-ntlmssp does a string comparison of the user/domain part using the current process locale settings.
            # To ensure it matches the credentials we specify with the non-ascii chars we need to ensure the locale is
            # something that can support UTF-8 character comparison. macOS can fail with unknown locale on getlocale(),
            # just default to env vars if this get fails.
            try:
                original_locale = locale.getlocale(locale.LC_CTYPE)
            except ValueError:
                original_locale = None

            def cleanup() -> None:
                locale.setlocale(locale.LC_CTYPE, original_locale)

            locale.setlocale(locale.LC_CTYPE, "en_US.UTF-8")

        tmp_creds = os.path.join(to_text(tmpdir), "pÿspᴞӛgӫ TÈ$" ".creds")
        with open(tmp_creds, mode="wb") as fd:
            fd.write(to_bytes("%s:%s:%s" % (domain, username, password)))

        monkeypatch.setenv("NTLM_USER_FILE", to_text(tmp_creds))

        yield "%s\\%s" % (domain, username), password

    finally:
        if cleanup:
            cleanup()


@pytest.fixture()
def kerb_cred(monkeypatch):
    if not HAS_K5TEST:
        pytest.skip("Cannot create Kerberos credential without k5test being installed")

    realm = K5Realm()
    try:
        for k, v in realm.env.items():
            monkeypatch.setenv(to_text(k), to_text(v))

        yield realm

    finally:
        realm.stop()
        del realm
