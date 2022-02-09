# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

import spnego._context as con


@pytest.mark.parametrize(
    "value, expected_domain, expected_user",
    [
        (None, None, None),
        ("username", None, "username"),
        ("domain\\username", "domain", "username"),
        ("username@DOMAIN.COM", None, "username@DOMAIN.COM"),
    ],
)
def test_split_username(value, expected_domain, expected_user):
    actual_domain, actual_user = con.split_username(value)

    assert actual_domain == expected_domain
    assert actual_user == expected_user


def test_gss_mech_native_labels():
    actual = con.GSSMech.native_labels()

    assert isinstance(actual, dict)
    assert actual[con.GSSMech.ntlm] == "NTLM"
    assert actual[con.GSSMech.ntlm.value] == "NTLM"


@pytest.mark.parametrize(
    "value, expected",
    [
        (con.GSSMech.ntlm, False),
        (con.GSSMech.spnego, False),
        (con.GSSMech.kerberos_u2u, False),
        (con.GSSMech.kerberos, True),
        (con.GSSMech._ms_kerberos, True),
        (con.GSSMech._kerberos_draft, True),
        (con.GSSMech._iakerb, True),
    ],
)
def test_gss_mech_is_kerberos_oid(value, expected):
    assert value.is_kerberos_oid == expected
