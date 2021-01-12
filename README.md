# Python SPNEGO Library

[![Build Status](https://dev.azure.com/jborean93/jborean93/_apis/build/status/jborean93.pyspnego?branchName=main)](https://dev.azure.com/jborean93/jborean93/_build/latest?definitionId=2&branchName=main)
[![codecov](https://codecov.io/gh/jborean93/pyspnego/branch/main/graph/badge.svg)](https://codecov.io/gh/jborean93/pyspnego)
[![PyPI version](https://badge.fury.io/py/pyspnego.svg)](https://badge.fury.io/py/pyspnego)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/pyspnego/blob/master/LICENSE)

Library to handle SPNEGO (Negotiate, NTLM, Kerberos) authentication. Also includes a packet parser that can be used to
decode raw NTLM/SPNEGO/Kerberos tokens into a human readable format.


## Requirements

See [How to Install](#how-to-install) for more details

* CPython 2.7, 3.5+
* [cryptography](https://github.com/pyca/cryptography)

### Optional Requirements

The following Python libraries can be installed to add extra features that do not come with the base package:

* [python-gssapi](https://github.com/pythongssapi/python-gssapi) for Kerberos authentication on Linux
* [ruamel.yaml](https://pypi.org/project/ruamel.yaml/) for YAML output support on `pyspnego-parse`


## How to Install

To install pyspnego with all basic features, run

```bash
pip install pyspnego
```

### Kerberos Authentication

While pyspnego supports Kerberos authentication on Linux, it isn't included by default due to its reliance on system
packages to be present.

To install these packages, run the below

```bash
# Debian/Ubuntu - Python 2
apt-get install gcc python-dev libkrb5-dev

# Debian/Ubuntu - Python 3
apt-get install gcc python3-dev libkrb5-dev

# Centos/RHEL
yum install gcc python-devel krb5-devel

# Fedora
dnf install gcc python-devel krb5-devel

# Arch Linux
pacman -S gcc krb5
```

Once installed you can install the Python packages with

```bash
pip install pyspnego[kerberos]
```

Kerberos also needs to be configured to talk to the domain but that is outside the scope of this page.

While NTLM auth works out of the box, it is recommended to install the
[gss-ntlmssp](https://github.com/gssapi/gss-ntlmssp) library for full Negotiate support. This can be done with

```bash
# Debian/Ubuntu
apt-get install gss-ntlmssp

# Centos/RHEL
yum install gssntlmssp

# Fedora
dnf install gssntlmssp

# Arch Linux
# AUR package https://aur.archlinux.org/packages/gss-ntlmssp/
```


## How to Use

See [the examples section](docs/examples) for examples on how to use the authentication side of the library.

_Note: While server/acceptor authentication is available for all protocols it is highly recommended you have the system GSSAPI and NTLM system libraries present for acceptor authentication. Pyspnego NTLM acceptor authentication should work but it is not as thoroughly tested as the GSSAPI imlpementation._


## Backlog

* Add support for anonymous authentication
* See if `pywinrm` wants to use this
