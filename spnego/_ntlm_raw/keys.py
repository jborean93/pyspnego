# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import hashlib
import hmac
import io
from typing import Optional

from spnego._ntlm_raw.des import (
    DES,
)

from spnego._text import (
    text_type,
    to_bytes,
)


def lmowfv1(password):  # type: (text_type) -> bytes
    """NTLMv1 LMOWFv1 function

    The Lan Manager v1 one way function as documented under `NTLM v1 Authentication`_.

    The pseudo-code for this function is::

        Define LMOWFv1(Passwd, User, UserDom) as
            ConcatenationOf( DES( UpperCase( Passwd)[0..6],"KGS!@#$%"),
                DES( UpperCase( Passwd)[7..13],"KGS!@#$%"))

    Args:
        password: The password for the user.

    Returns:
        bytes: The LMv1 one way hash of the user's password.

    .. _NTLM v1 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
    """
    # Fix the password to upper case and pad the length to exactly 14 bytes.
    b_password = to_bytes(password.upper()).ljust(14, b"\x00")[:14]

    b_hash = io.BytesIO()
    for start, end in [(0, 7), (7, 14)]:
        des = DES(DES.key56_to_key64(b_password[start:end]))
        b_hash.write(des.encrypt(b"KGS!@#$%"))

    return b_hash.getvalue()


def ntowfv1(password):  # type: (text_type) -> bytes
    """NTLMv1 NTOWFv1 function

    The NT v1 one way function as documented under `NTLM v1 Authentication`_.

    The pseudo-code for this function is::

        Define NTOWFv1(Passwd, User, UserDom) as MD4(UNICODE(Passwd))

    Args:
        password: The password for the user.

    Returns:
        bytes: The NTv1 one way hash of the user's password.

    .. _NTLM v1 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
    """
    return hashlib.new('md4', to_bytes(password, encoding='utf-16-le')).digest()


def ntowfv2(username, password, domain_name):  # type: (text_type, text_type, Optional[text_type]) -> bytes
    """NTLMv2 NTOWFv2 function

    The NT v2 one way function as documented under `NTLM v2 Authentication`_.

    The pseudo-code for this function is::

        Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
            MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )

    Args:

    Returns:
        bytes: The NTv2 one way has of the user's credentials.

    .. _NTLM v2 Authentication:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
    """
    digest = ntowfv1(password)  # ntowfv1 creates the MD4 hash of the user's password.
    b_user = to_bytes(username.upper() + (domain_name or u""), encoding='utf-16-le')
    return hmac.new(digest, b_user, digestmod=hashlib.md5).digest()


lmowfv2 = ntowfv2
