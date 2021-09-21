# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest


def test_gss_import_dep():
    with pytest.deprecated_call(match="spnego.gss is deprecated and will be removed in a future release"):
        import spnego.gss


def test_negotiate_import_dep():
    with pytest.deprecated_call(match="spnego.negotiate is deprecated and will be removed in a future release"):
        import spnego.negotiate


def test_ntlm_import_dep():
    with pytest.deprecated_call(match="spnego.ntlm is deprecated and will be removed in a future release"):
        import spnego.ntlm


def test_sspi_import_dep():
    with pytest.deprecated_call(match="spnego.sspi is deprecated and will be removed in a future release"):
        import spnego.sspi
