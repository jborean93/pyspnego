#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import sys

from setuptools import Extension, setup


def abs_path(rel_path):
    return os.path.join(os.path.dirname(__file__), rel_path)


def get_version(rel_path):
    with open(abs_path(rel_path), mode='r') as version_fd:
        for line in version_fd.readlines():

            if line.startswith('__version__'):
                delim = '"' if '"' in line else "'"

                return line.split(delim)[1]

        else:
            raise RuntimeError("Unable to find version string.")


with open(abs_path('README.md'), mode='rb') as fd:
    long_description = fd.read().decode('utf-8')

extensions = None

if os.name == 'nt':
    from Cython.Build import cythonize

    try:
        sys.argv.remove('--cython-linetrace')
        cython_linetrace = True
    except ValueError:
        cython_linetrace = False

    def build_sspi_extension(name, libraries):
        rel_path = os.path.join('spnego', '_sspi_raw', name)

        if not isinstance(libraries, list):
            libraries = [libraries]

        return Extension(
            name=rel_path.replace(os.path.sep, '.'),
            sources=[rel_path + '.pyx'],
            libraries=libraries,
            define_macros=[('UNICODE', '1'), ('_UNICODE', '1'), ('SECURITY_WIN32', '1')]
        )

    extensions = cythonize([
        build_sspi_extension('sspi', 'Secur32'),
        build_sspi_extension('text', 'Kernel32'),
    ], language_level=3, compiler_directives={'linetrace': cython_linetrace})


setup(
    name='pyspnego',
    version=get_version(os.path.join('spnego', '_version.py')),
    packages=['spnego', 'spnego._ntlm_raw', 'spnego._sspi_raw'],
    scripts=[
        'bin/pyspnego-parse',
    ],
    ext_modules=extensions,
    include_package_data=True,
    install_requires=[
        'cryptography',
    ],
    extras_require={
        ':python_version<"3.5"': [
            'enum34',
        ],
        'kerberos:sys_platform=="win32"': [],
        'kerberos:sys_platform!="win32"': [
            'gssapi>=1.5.0',
        ],
        'yaml': [
            'ruamel.yaml',
        ],
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/pyspnego',
    description='Windows Negotiate Authentication Client and Server',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='windows spnego negotiate ntlm kerberos sspi gssapi auth',
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
