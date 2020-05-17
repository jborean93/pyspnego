# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import locale
import os
import pytest
import socket

from spnego._text import (
    to_bytes,
    to_native,
    to_text,
)


@pytest.fixture()
def ntlm_cred(tmpdir, monkeypatch):
    cleanup = None
    try:
        # Use unicode credentials to test out edge cases when dealing with non-ascii chars.
        username = u'ÜseӜ'
        password = u'Pӓ$sw0r̈d'

        if os.name == 'nt':
            domain = to_text(socket.gethostname())

            # TODO: create test user here on Windows.
            def cleanup():
                pass

        else:
            domain = u'Dȫm̈Ąiᴞ'

            # gss-ntlmssp does a string comparison of the user/domain part using the current process locale settings.
            # To ensure it matches the credentials we specify with the non-ascii chars we need to ensure the locale is
            # something that can support UTF-8 character comparison. macOS can fail with unknown locale on getlocale(),
            # just default to env vars if this get fails.
            try:
                original_locale = locale.getlocale(locale.LC_CTYPE)
            except ValueError:
                original_locale = (None, None)

            def cleanup():
                locale.setlocale(locale.LC_CTYPE, original_locale)

            locale.setlocale(locale.LC_CTYPE, 'en_US.UTF-8')

        tmp_creds = os.path.join(to_text(tmpdir), u'pÿspᴞӛgӫ TÈ$''.creds')
        with open(tmp_creds, mode='wb') as fd:
            fd.write(to_bytes(u'%s:%s:%s' % (domain, username, password)))

        monkeypatch.setenv('NTLM_USER_FILE', to_native(tmp_creds))

        yield u"%s\\%s" % (domain, username), password

    finally:
        if cleanup:
            cleanup()
