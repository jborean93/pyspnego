# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import base64
import os
import pytest
import re

import spnego.ntlm as ntlm

from spnego._text import (
    to_bytes,
    to_native,
    to_text,
)

from spnego.exceptions import (
    OperationNotAvailableError,
    SpnegoError,
)


def test_get_credential_file_no_env_var():
    actual = ntlm._get_credential_file()
    assert actual is None


def test_get_credential_file_env_var_missing_file(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')

    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))

    actual = ntlm._get_credential_file()
    assert actual is None


def test_get_credential_file(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    with open(tmp_creds, mode='wb') as fd:
        fd.write(b"data")

    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))

    actual = ntlm._get_credential_file()
    assert actual == to_text(tmp_creds)


@pytest.mark.parametrize('line, username, domain, lm_hash, nt_hash', [
    ('domain:Username:password', 'username', 'domain',
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    ('fake\ndomain:username:password', 'username', 'domain',  # newline or garbage data  in file won't fail
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    (':username@DOMAIN.COM:password', 'username@DOMAIN.COM', None,
     'E52CAC67419A9A224A3B108F3FA6CB6D', '8846F7EAEE8FB117AD06BDD830B7586C'),
    ('testuser:1000:278623D830DABE161104594F8C2EF12B:C3C6F4FD8A02A6C1268F1A8074B6E7E0:[U]:LCT-1589398321',
     'testuser', None, '278623D830DABE161104594F8C2EF12B', 'C3C6F4FD8A02A6C1268F1A8074B6E7E0'),
    ('TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321',
     'testuser', 'testdom', '4588C64B89437893AAD3B435B51404EE', '65202355FA01AEF26B89B19E00F52679'),
    ('TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321',
     'testuser', 'testdom', '4588C64B89437893AAD3B435B51404EE', '65202355FA01AEF26B89B19E00F52679'),
    ('testuser@TESTDOM.COM:1000:00000000000000000000000000000000:8ADB9B997580D69E69CAA2BBB68F4697:[U]:LCT-1589398321',
     'testuser@testdom.com', '', '00000000000000000000000000000000', '8ADB9B997580D69E69CAA2BBB68F4697'),
])
def test_get_credential_from_file(line, username, domain, lm_hash, nt_hash, tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))
    with open(tmp_creds, mode='wb') as fd:
        fd.write(to_bytes(line))

    actual = ntlm._NTLMCredential(username, domain)

    assert actual.username == username
    assert actual.domain == domain
    assert actual.lm_hash == base64.b16decode(lm_hash)
    assert actual.nt_hash == base64.b16decode(nt_hash)


def test_get_credential_from_file_no_matches(tmpdir, monkeypatch):
    tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
    monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))
    with open(tmp_creds, mode='wb') as fd:
        fd.write(b'domain:username:password')

    with pytest.raises(SpnegoError, match="Failed to find any matching credential in NTLM_USER_FILE "
                                          "credential store."):
        ntlm._NTLMCredential("username", "fake")


@pytest.mark.parametrize('level', [-1, 6])
def test_invalid_lm_compat_level(level, monkeypatch):
    monkeypatch.setenv('LM_COMPAT_LEVEL', to_native(level))

    expected = "Invalid LM_COMPAT_LEVEL %s, must be between 0 and 5" % level
    with pytest.raises(SpnegoError, match=re.escape(expected)):
        ntlm.NTLMProxy("user", "pass")


@pytest.mark.parametrize('usage', ['initiate', 'accept'])
def test_context_no_store(usage):
    with pytest.raises(OperationNotAvailableError, match="Retrieving NTLM store without NTLM_USER_FILE set to a "
                                                         "filepath"):
        ntlm.NTLMProxy(None, None, usage=usage)


def test_iov_available():
    assert ntlm.NTLMProxy.iov_available() is False
