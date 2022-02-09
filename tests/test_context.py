# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

import spnego._context as context


@pytest.mark.parametrize(
    "value, expected_domain, expected_user",
    [
        (None, None, None),
        ("username", None, "username"),
        ("domain\\username", "domain", "username"),
        ("domain\\username\\part", "domain", "username\\part"),
        ("username@domain", None, "username@domain"),
    ],
)
def test_split_username(value, expected_domain, expected_user):
    actual_domain, actual_user = context.split_username(value)

    assert actual_domain == expected_domain
    assert actual_user == expected_user


@pytest.mark.parametrize(
    "value, expected",
    [
        (context.GSSMech.ntlm, "ntlm"),
        (context.GSSMech.spnego, "spnego"),
        (context.GSSMech.kerberos, "kerberos"),
        (context.GSSMech._ms_kerberos, "kerberos"),
        (context.GSSMech._kerberos_draft, "kerberos"),
        (context.GSSMech._iakerb, "kerberos"),
    ],
)
def test_gss_mech_common_name(value, expected):
    actual = context.GSSMech(value).common_name

    assert actual == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (context.GSSMech.ntlm, False),
        (context.GSSMech.spnego, False),
        (context.GSSMech.kerberos, True),
        (context.GSSMech._ms_kerberos, True),
        (context.GSSMech._kerberos_draft, True),
        (context.GSSMech._iakerb, True),
    ],
)
def test_gss_mech_is_kerberos_oid(value, expected):
    assert context.GSSMech(value).is_kerberos_oid == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.3.6.1.4.1.311.2.2.10", context.GSSMech.ntlm),
        ("1.3.6.1.5.5.2", context.GSSMech.spnego),
        ("1.2.840.113554.1.2.2", context.GSSMech.kerberos),
        ("1.2.840.48018.1.2.2", context.GSSMech._ms_kerberos),
    ],
)
def test_gss_mech_from_oid(value, expected):
    actual = context.GSSMech.from_oid(value)

    assert actual == expected


def test_gss_mech_from_oid_invalid():
    with pytest.raises(ValueError, match="is not a valid GSSMech OID"):
        context.GSSMech.from_oid("1.2.3.4.5")
