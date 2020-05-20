# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import re

import pytest

import spnego.exceptions as exceptions

try:
    from gssapi.exceptions import GSSError
except ImportError:
    GSSError = ()

try:
    WinError = WindowsError
except NameError:
    WinError = ()


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
    assert actual.message == 'SpnegoError (1024): Unknown error code'


def test_invalid_token_error():
    actual = exceptions.SpnegoError(exceptions.ErrorCode.invalid_token)

    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error is None
    assert actual.message == 'SpnegoError (9): A token was invalid'


def test_invalid_token_error_with_context():
    actual = exceptions.InvalidTokenError(context_msg="Context")

    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error is None
    assert actual.message == 'SpnegoError (9): A token was invalid, Context: Context'


@pytest.mark.skipif(not GSSError, reason='Need a GSSError to test this out')
def test_invalid_token_from_gssapi():
    base_error = GSSError(589824, 0)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error == base_error
    assert actual.message.startswith('SpnegoError (9): Major (589824)')


# FIXME: implement these tests on Windows for validation.
@pytest.mark.skipif(not WinError, reason='Need a WindowsError to test this out')
def test_invalid_token_from_sspi():
    a = ''


def test_operation_not_available_error():
    actual = exceptions.SpnegoError(exceptions.ErrorCode.unavailable)

    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error is None
    assert actual.message == 'SpnegoError (16): Operation not supported or available'


def test_operation_not_available_error_with_context():
    actual = exceptions.OperationNotAvailableError(context_msg="Context")

    assert isinstance(actual, exceptions.OperationNotAvailableError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.unavailable
    assert actual.base_error is None
    assert actual.message == 'SpnegoError (16): Operation not supported or available, Context: Context'


@pytest.mark.skipif(not GSSError, reason='Need a GSSError to test this out')
def test_operation_not_available_from_gssapi():
    base_error = GSSError(589824, 0)

    actual = exceptions.SpnegoError(base_error=base_error)
    assert isinstance(actual, exceptions.InvalidTokenError)
    assert actual.ERROR_CODE == exceptions.ErrorCode.invalid_token
    assert actual.base_error == base_error
    assert actual.message.startswith('SpnegoError (9): Major (589824): ')


# FIXME: implement these tests on Windows for validation.
@pytest.mark.skipif(not WinError, reason='Need a WindowsError to test this out')
def test_operation_not_available_from_sspi():
    a = ''
