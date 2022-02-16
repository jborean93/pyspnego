#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import glob
import os
import os.path
import typing

from setuptools import Extension, find_packages, setup
from setuptools.command.sdist import sdist

SKIP_CYTHON_FILE = "__dont_use_cython__.txt"


def abs_path(rel_path: str) -> str:
    return os.path.join(os.path.dirname(__file__), rel_path)


def get_version(
    rel_path: str,
) -> str:
    with open(abs_path(rel_path), mode="r") as version_fd:
        for line in version_fd.readlines():

            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"

                return line.split(delim)[1]

        else:
            raise RuntimeError("Unable to find version string.")


with open(abs_path("README.md"), mode="rb") as fd:
    long_description = fd.read().decode("utf-8")

extensions = None

if os.name == "nt" or os.environ.get("SPNEGO_FORCE_CYTHONIZE", "").lower() == "true":
    if os.path.exists(SKIP_CYTHON_FILE):
        print("In distributed package, building from C files...")
        SOURCE_EXT = "c"
    else:
        try:
            from Cython.Build import cythonize

            print("Building from Cython files...")
            SOURCE_EXT = "pyx"
        except ImportError:
            print("Cython not found, building from C files...")
            SOURCE_EXT = "c"

    def build_sspi_extension(
        name: str,
        libraries: typing.Union[typing.List[str], str],
    ) -> Extension:
        rel_path = os.path.join("src", "spnego", "_sspi_raw", name)

        if SOURCE_EXT == "c" and not os.path.exists(abs_path(f"{rel_path}.c")):
            raise Exception("SSPI C files not found, ensure Cython is installed to generate from source.")

        if not isinstance(libraries, list):
            libraries = [libraries]

        return Extension(
            name=".".join(rel_path.split(os.path.sep)[1:]),
            sources=[f"{rel_path}.{SOURCE_EXT}"],
            libraries=libraries,
            define_macros=[("UNICODE", "1"), ("_UNICODE", "1"), ("SECURITY_WIN32", "1")],
        )

    extensions = [
        build_sspi_extension("sspi", "Secur32"),
        build_sspi_extension("text", "Kernel32"),
    ]
    if SOURCE_EXT == "pyx":
        extensions = cythonize(extensions, language_level=3)


class sdist_spnego(sdist):
    def run(self) -> None:
        if not self.dry_run:
            with open(SKIP_CYTHON_FILE, mode="wb") as flag_file:
                flag_file.write(b"")

            sdist.run(self)

            os.remove(SKIP_CYTHON_FILE)


setup(
    name="pyspnego",
    version=get_version(os.path.join("src", "spnego", "_version.py")),
    packages=find_packages(where="src"),
    package_data={
        "spnego": ["py.typed"],
        "spnego._sspi_raw": ["*.pyi"],
    },
    package_dir={"": "src"},
    entry_points={"console_scripts": ["pyspnego-parse = spnego.__main__:main"]},
    ext_modules=extensions,
    zip_safe=False,
    cmdclass={
        "sdist": sdist_spnego,
    },
    install_requires=[
        "cryptography",
    ],
    extras_require={
        ':python_version<"3.7"': [
            "dataclasses",
        ],
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            "gssapi>=1.5.0",
            "krb5>=0.3.0",
        ],
        "yaml": [
            "ruamel.yaml",
        ],
    },
    author="Jordan Borean",
    author_email="jborean93@gmail.com",
    url="https://github.com/jborean93/pyspnego",
    description="Windows Negotiate Authentication Client and Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="windows spnego negotiate ntlm kerberos sspi gssapi auth",
    license="MIT",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
