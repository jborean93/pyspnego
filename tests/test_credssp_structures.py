# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

import spnego._credssp_structures as credssp

from .conftest import get_data


def test_unpack_missing_text_field():
    with pytest.raises(ValueError, match="Missing mandatory text field 'field' in 'structure'"):
        credssp.unpack_text_field({}, 0, "structure", "field")


def test_ts_request_pack():
    expected = get_data("credssp_ts_request")

    actual = credssp.TSRequest(6, credssp.NegoData(b"123"), b"auth info", b"pub key auth", 10, b"client nonce").pack()

    assert actual == expected


def test_ts_request_unpack():
    data = get_data("credssp_ts_request")

    actual = credssp.TSRequest.unpack(data)

    assert isinstance(actual, credssp.TSRequest)
    assert actual.version == 6
    assert isinstance(actual.nego_tokens, list)
    assert len(actual.nego_tokens) == 1
    assert isinstance(actual.nego_tokens[0], credssp.NegoData)
    assert actual.nego_tokens[0].nego_token == b"123"
    assert actual.auth_info == b"auth info"
    assert actual.pub_key_auth == b"pub key auth"
    assert actual.error_code == 10
    assert actual.client_nonce == b"client nonce"


def test_ts_credential_unknown_credential_type():
    credential = credssp.TSCredentials("failure")  # type: ignore[arg-type] # Testing this scenario

    with pytest.raises(ValueError, match="Invalid credential type set"):
        _ = credential.cred_type


def test_ts_credential_unknown_credential_type_unpack():
    data = get_data("credssp_ts_credential_password")
    # Manually change the credType to 0 in a known good structure.
    data = data[:6] + b"\x00" + data[7:]

    with pytest.raises(ValueError, match="Unknown credType 0 in TSCredentials, cannot unpack"):
        credssp.TSCredentials.unpack(data)


def test_ts_credential_password_pack():
    expected = get_data("credssp_ts_credential_password")
    actual = credssp.TSCredentials(
        credssp.TSPasswordCreds(
            "domain name",
            "username",
            "password",
        )
    ).pack()

    assert actual == expected


def test_ts_credential_password_unpack():
    data = get_data("credssp_ts_credential_password")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 1
    assert isinstance(actual.credentials, credssp.TSPasswordCreds)
    assert actual.credentials.domain_name == "domain name"
    assert actual.credentials.username == "username"
    assert actual.credentials.password == "password"


def test_ts_credential_smart_card_pack():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94846575-5a58-44de-b07b-48b90af328fb
    expected = get_data("credssp_ts_credential_smart_card")

    actual = credssp.TSCredentials(
        credssp.TSSmartCardCreds(
            "bbbbbbbbbbbb",
            credssp.TSCspDataDetail(
                1,
                reader_name="OMNIKEY CardMan 3x21 0",
                container_name="le-MSSmartcardUser-8bda019f-1266--53268",
                csp_name="Microsoft Base Smart Card Crypto Provider",
            ),
        )
    ).pack()

    assert actual == expected


def test_ts_credential_smart_card_unpack():
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94846575-5a58-44de-b07b-48b90af328fb
    data = get_data("credssp_ts_credential_smart_card")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 2
    assert isinstance(actual.credentials, credssp.TSSmartCardCreds)
    assert actual.credentials.pin == "bbbbbbbbbbbb"
    assert isinstance(actual.credentials.csp_data, credssp.TSCspDataDetail)
    assert actual.credentials.csp_data.key_spec == 1
    assert actual.credentials.csp_data.card_name is None
    assert actual.credentials.csp_data.reader_name == "OMNIKEY CardMan 3x21 0"
    assert actual.credentials.csp_data.container_name == "le-MSSmartcardUser-8bda019f-1266--53268"
    assert actual.credentials.csp_data.csp_name == "Microsoft Base Smart Card Crypto Provider"
    assert actual.credentials.user_hint is None
    assert actual.credentials.domain_hint is None


def test_ts_credential_smart_card_full_pack():
    expected = get_data("credssp_ts_credential_smart_card_full")

    actual = credssp.TSCredentials(
        credssp.TSSmartCardCreds(
            "bbbbbbbbbbbb",
            credssp.TSCspDataDetail(
                1,
                card_name="Card Name",
                reader_name="OMNIKEY CardMan 3x21 0",
                container_name="le-MSSmartcardUser-8bda019f-1266--53268",
                csp_name="Microsoft Base Smart Card Crypto Provider",
            ),
            "user_hint",
            "domain_hint",
        )
    ).pack()

    assert actual == expected


def test_ts_credential_smart_card_full_unpack():
    data = get_data("credssp_ts_credential_smart_card_full")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 2
    assert isinstance(actual.credentials, credssp.TSSmartCardCreds)
    assert actual.credentials.pin == "bbbbbbbbbbbb"
    assert isinstance(actual.credentials.csp_data, credssp.TSCspDataDetail)
    assert actual.credentials.csp_data.key_spec == 1
    assert actual.credentials.csp_data.card_name == "Card Name"
    assert actual.credentials.csp_data.reader_name == "OMNIKEY CardMan 3x21 0"
    assert actual.credentials.csp_data.container_name == "le-MSSmartcardUser-8bda019f-1266--53268"
    assert actual.credentials.csp_data.csp_name == "Microsoft Base Smart Card Crypto Provider"
    assert actual.credentials.user_hint == "user_hint"
    assert actual.credentials.domain_hint == "domain_hint"


def test_ts_credential_remote_guard_multiple_pack():
    expected = get_data("credssp_ts_credential_remote_guard_multiple")

    actual = credssp.TSCredentials(
        credssp.TSRemoteGuardCreds(
            credssp.TSRemoteGuardPackageCred("Package 1", b"123"),
            [
                credssp.TSRemoteGuardPackageCred("Package 2", b"456"),
                credssp.TSRemoteGuardPackageCred("Package 3", b"789"),
            ],
        )
    ).pack()

    assert actual == expected


def test_ts_credential_remote_guard_multiple_unpack():
    data = get_data("credssp_ts_credential_remote_guard_multiple")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 6
    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)

    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)
    assert isinstance(actual.credentials.logon_cred, credssp.TSRemoteGuardPackageCred)
    assert actual.credentials.logon_cred.package_name == "Package 1"
    assert actual.credentials.logon_cred.cred_buffer == b"123"
    assert isinstance(actual.credentials.supplemental_creds, list)
    assert len(actual.credentials.supplemental_creds) == 2
    assert isinstance(actual.credentials.supplemental_creds[0], credssp.TSRemoteGuardPackageCred)
    assert actual.credentials.supplemental_creds[0].package_name == "Package 2"
    assert actual.credentials.supplemental_creds[0].cred_buffer == b"456"
    assert isinstance(actual.credentials.supplemental_creds[1], credssp.TSRemoteGuardPackageCred)
    assert actual.credentials.supplemental_creds[1].package_name == "Package 3"
    assert actual.credentials.supplemental_creds[1].cred_buffer == b"789"


def test_ts_credential_remote_guard_no_supplemental_pack():
    expected = get_data("credssp_ts_credential_remote_guard_no_supplemental")

    actual = credssp.TSCredentials(
        credssp.TSRemoteGuardCreds(
            credssp.TSRemoteGuardPackageCred("Package 1", b"123"),
        )
    ).pack()

    assert actual == expected


def test_ts_credential_remote_guard_no_supplemental_unpack():
    data = get_data("credssp_ts_credential_remote_guard_no_supplemental")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 6
    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)

    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)
    assert isinstance(actual.credentials.logon_cred, credssp.TSRemoteGuardPackageCred)
    assert actual.credentials.logon_cred.package_name == "Package 1"
    assert actual.credentials.logon_cred.cred_buffer == b"123"
    assert actual.credentials.supplemental_creds is None


def test_ts_credential_remote_guard_empty_supplemental_pack():
    expected = get_data("credssp_ts_credential_remote_guard_empty_supplemental")

    actual = credssp.TSCredentials(
        credssp.TSRemoteGuardCreds(credssp.TSRemoteGuardPackageCred("Package 1", b"123"), [])
    ).pack()

    assert actual == expected


def test_ts_credential_remote_guard_empty_supplemental_unpack():
    data = get_data("credssp_ts_credential_remote_guard_empty_supplemental")
    actual = credssp.TSCredentials.unpack(data)

    assert isinstance(actual, credssp.TSCredentials)
    assert actual.cred_type == 6
    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)

    assert isinstance(actual.credentials, credssp.TSRemoteGuardCreds)
    assert isinstance(actual.credentials.logon_cred, credssp.TSRemoteGuardPackageCred)
    assert actual.credentials.logon_cred.package_name == "Package 1"
    assert actual.credentials.logon_cred.cred_buffer == b"123"
    assert actual.credentials.supplemental_creds == []


def test_ts_remote_guard_pack():
    # Based on https://interopevents.blob.core.windows.net/events/2018/rdp/day3/577741-Remote%20Credencial%20Guard.pdf
    expected = get_data("credssp_ts_remote_guard_ms_example")

    actual = credssp.TSRemoteGuardCreds(
        credssp.TSRemoteGuardPackageCred("Kerberos", b"\x11" * 2611),
        credssp.TSRemoteGuardPackageCred("NTLM", b"\x22" * 204),
    ).pack()

    assert actual == expected


def test_ts_remote_guard_unpack():
    # Based on https://interopevents.blob.core.windows.net/events/2018/rdp/day3/577741-Remote%20Credencial%20Guard.pdf
    data = get_data("credssp_ts_remote_guard_ms_example")
    actual = credssp.TSRemoteGuardCreds.unpack(data)

    assert isinstance(actual, credssp.TSRemoteGuardCreds)
    assert isinstance(actual.logon_cred, credssp.TSRemoteGuardPackageCred)
    assert actual.logon_cred.package_name == "Kerberos"
    assert actual.logon_cred.cred_buffer == b"\x11" * 2611
    assert isinstance(actual.supplemental_creds, list)
    assert len(actual.supplemental_creds) == 1
    assert isinstance(actual.supplemental_creds[0], credssp.TSRemoteGuardPackageCred)
    assert actual.supplemental_creds[0].package_name == "NTLM"
    assert actual.supplemental_creds[0].cred_buffer == b"\x22" * 204
