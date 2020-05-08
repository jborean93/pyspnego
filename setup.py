#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os.path

from setuptools import Extension, setup
from Cython.Build import cythonize


with open(os.path.join(os.path.dirname(__file__), 'README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')


extensions = [
    Extension(
        name='spnego._sspi_raw.sspi',
        sources=['spnego/_sspi_raw/sspi.pyx'],
        libraries=['Secur32'],
        define_macros=[('UNICODE', '1'), ('_UNICODE', '1'), ('SECURITY_WIN32', '1')],
    ),
    Extension(
        name='spnego._sspi_raw.text',
        sources=['spnego/_sspi_raw/text.pyx'],
        libraries=['Kernel32'],
        define_macros=[('UNICODE', '1'), ('_UNICODE', '1')],
    ),
]

setup(
    name='pyspnego',
    version='0.0.1.dev0',  # FIXME: read spnego/_version.py' for __version__ string.
    packages=['spnego', 'spnego._ntlm_raw', 'spnego._sspi_raw'],
    scripts=[
        'bin/pyspnego-parse',
    ],
    ext_modules=cythonize(extensions, language_level=3),
    include_package_data=True,
    install_requires=[
        'cryptography',
    ],
    extras_require={
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.5.0'
        ],
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pyspnego',
    description='Windows Negotiate Authentication CLient',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='windows spnego negotiate ntlm kerberos sspi gssapi',
    license='MIT',
    python_requires='>=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
