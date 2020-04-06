#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os.path

from setuptools import setup


with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as fd:
    long_description = fd.read()


setup(
    name='pyspnego',
    version='0.0.1.dev0',
    packages=['spnego'],
    scripts=[
        'bin/pyspnego-parse',
    ],
    include_package_data=True,
    install_requires=[
        'ntlm-auth>=1.2.0',
    ],
    extras_require={
        'kerberos:sys_platform=="win32"': [
            'pywin32'
        ],
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
