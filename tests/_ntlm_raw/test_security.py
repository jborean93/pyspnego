# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

from spnego._ntlm_raw.crypto import (
    kxkey,
    rc4init,
    sealkey,
    signkey,
)

import spnego._ntlm_raw.security as security

from spnego._text import (
    to_bytes,
    to_text,
)

from .._ntlm_raw import (
    TEST_CLIENT_CHALLENGE,
    TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS,
    TEST_NTLMV1_FLAGS,
    TEST_PASSWD,
    TEST_RANDOM_SESSION_KEY,
    TEST_SERVER_CHALLENGE,
    TEST_TIME,
    TEST_USER,
    TEST_USER_DOM,
)


def test_seal_ntlmv1():
    key_exchange_key = b"\xD8\x72\x62\xB0\xCD\xE4\xB1\xCB\x74\x99\xBE\xCC\xCD\xF1\x07\x84"

    seal_key = sealkey(TEST_NTLMV1_FLAGS, TEST_RANDOM_SESSION_KEY, usage='initiate')
    sign_key = signkey(TEST_NTLMV1_FLAGS, TEST_RANDOM_SESSION_KEY, usage='initiate')
    handle = rc4init(seal_key)

    actual_sig = security.sign(TEST_NTLMV1_FLAGS, handle, sign_key, 0,
                               to_bytes(u"Plaintext", encoding='utf-16-le'))


def test_seal_ntlmv2():
    a = ''
