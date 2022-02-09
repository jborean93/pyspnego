# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re

import pytest

import spnego.exceptions as exceptions

GSSError = exceptions.GSSError
WinError = exceptions.WinError


@pytest.mark.parametrize(
    "option, expected",
    [
        (
            exceptions.NegotiateOptions.negotiate_kerberos,
            "The Python gssapi library is not installed so Kerberos cannot " "be negotiated.",
        ),
        (
            exceptions.NegotiateOptions.wrapping_iov,
            "The system is missing the GSSAPI IOV extension headers or NTLM or "
            "CredSSP is being requested, cannot utilize wrap_iov and unwrap_iov",
        ),
        (
            exceptions.NegotiateOptions.wrapping_winrm,
            "The system is missing the GSSAPI IOV extension headers required " "for WinRM encryption with Kerberos.",
        ),
        (exceptions.NegotiateOptions.session_key, "The protocol selected does not support getting the session key."),
    ],
)
def test_feature_missing_error(option, expected):
    err = exceptions.FeatureMissingError(option)
    assert str(err) == expected
    assert err.message == expected


def test_spnego_error_no_code_fail():
    expected = "SpnegoError requires either an error_code or base_error"
    with pytest.raises(ValueError, match=re.escape(expected)):
        exceptions.SpnegoError()


def test_spnego_error_invalid_base_error_fail():
    expected = "base_error of type 'Exception' is not supported, must be a gssapi.exceptions.GSSError or WindowsError"
    with pytest.raises(ValueError, match=re.escape(expected)):
        exceptions.SpnegoError(base_error=Exception())


def test_spnego_error_unknown_error():
    actual = exceptions.SpnegoError(1024)

    assert isinstance(actual, exceptions.SpnegoError)
    assert actual.message == "SpnegoError (1024): Unknown error code"


def test_invalid_token_error():
    actual = exceptions.SpnegoError(exceptions.ErrorCode.invalid_token)

    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error is None
    assert actual.message == "SpnegoError (9): A token was invalid, or the logon was denied"


def test_invalid_token_error_with_context():
    actual = exceptions.InvalidTokenError(context_msg="Context")

    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error is None
    assert actual.message == "SpnegoError (9): A token was invalid, or the logon was denied, Context: Context"


@pytest.mark.skipif(GSSError == Exception, reason="Need a GSSError to test this out")
def test_invalid_token_from_gssapi():
    base_error = GSSError(589824, 0)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error == base_error
    assert actual.message.startswith("SpnegoError (9): Major (589824)")


@pytest.mark.skipif(WinError == Exception, reason="Need a WindowsError to test this out")
def test_invalid_token_from_sspi():
    base_error = WinError("Error")
    setattr(base_error, "winerror", -2146893048)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error == base_error
    assert actual.message.startswith("SpnegoError (9): ")


@pytest.mark.skipif(WinError == Exception, reason="Need a WindowsError to test this out")
def test_invalid_token_from_sspi_logon_denied():
    base_error = WinError("Error")
    setattr(base_error, "winerror", -2146893044)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error == base_error
    assert actual.message.startswith("SpnegoError (9): ")


def test_operation_not_available_error():
    actual = exceptions.SpnegoError(exceptions.ErrorCode.unavailable)

    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error is None
    assert actual.message == "SpnegoError (16): Operation not supported or available"


def test_operation_not_available_error_with_context():
    actual = exceptions.OperationNotAvailableError(context_msg="Context")

    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error is None
    assert actual.message == "SpnegoError (16): Operation not supported or available, Context: Context"


@pytest.mark.skipif(GSSError == Exception, reason="Need a GSSError to test this out")
def test_operation_not_available_from_gssapi():
    base_error = GSSError(1048576, 0)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error == base_error
    assert actual.message.startswith("SpnegoError (16): Major (1048576): ")


@pytest.mark.skipif(WinError == Exception, reason="Need a WindowsError to test this out")
def test_operation_not_available_from_sspi():
    base_error = WinError("Error")
    setattr(base_error, "winerror", -2146893054)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error == base_error
    assert actual.message.startswith("SpnegoError (16): ")
