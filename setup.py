#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import os.path
import typing

from setuptools import Extension, setup

extensions = None

if os.name == "nt":
    from Cython.Build import cythonize

    def build_sspi_extension(
        name: str,
        libraries: typing.Union[typing.List[str], str],
    ) -> Extension:
        rel_path = os.path.join("src", "spnego", "_sspi_raw", name)

        if not isinstance(libraries, list):
            libraries = [libraries]

        return Extension(
            name=".".join(rel_path.split(os.path.sep)[1:]),
            sources=[f"{rel_path}.pyx"],
            libraries=libraries,
            define_macros=[("UNICODE", "1"), ("_UNICODE", "1"), ("SECURITY_WIN32", "1")],
        )

    extensions = cythonize(
        [
            build_sspi_extension("sspi", "Secur32"),
            build_sspi_extension("text", "Kernel32"),
        ],
        language_level=3,
    )


setup(ext_modules=extensions)
