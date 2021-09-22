# Changelog

## 0.2.0 - 2021-09-22

### Breaking Changes

* Drop support for Python 2.7 and 3.5 - new minimum is 3.6+
* Made the `gss`, `negotiate`, `ntlm`, `sspi` exports private, use the `spnego.client` and `spnego.server` functions instead
  * A deprecation warning is raised when importing from these package directly and this will be removed in the next major release

### Features

* Added support for CredSSP authentication using `protocol='credssp'`
* Allow optional keyword arguments to be used with `spnego.client` and `spnego.server` to control authentication specific options

### Bugfixes

* Use Kerberos API to acquire Kerberos credential to get a forwardable token in a thread safe manner
* Fix default credential logic when no username is provided based on GSSAPI rules rather than just the default principal - https://github.com/jborean93/pyspnego/issues/15
* Ignore SPNEGO `mechListMIC` if it contains the same value as the `responseToken` due to an old Windows SPNEGO logic bug - https://github.com/krb5/krb5/blob/3f5a348287646d65700854650fe668b9c4249013/src/lib/gssapi/spnego/spnego_mech.c#L3734-L3744
* Do not use SSPI when `auth='ntlm'` and the password is in the form `{lm_hash}:{nt_hash}`


## 0.1.6 - 2021-05-07

* This will be the last release that supports Python 2.7 and 3.5
* Change enum type of `iov.BufferType` to `IntEnum` to fix load on Python 3.10 - https://github.com/jborean93/pyspnego/issues/10
* Make `pyspnego-parse` and entry point which uses `__main__.py` in the `spnego` package
  * This allows Windows (and Linux) users to use the parser script by running `python -m spnego --token ...`

## 0.1.5 - 2021-01-12

* Respect `NETBIOS_COMPUTER_NAME` when getting the workstation name for NTLM tokens. This matches the behaviour of `gss-ntlmssp` to ensure a consistent approach.

## 0.1.4 - 2020-12-02

* Only send `negState: request-mic` for the first reply from an acceptor for Negotiate auth.
  * Strict interpretations of SPNEGO will fail if the initiator sends this state as it is against the RFC.

## 0.1.3 - 2020-10-29

* Added Python 3.9 to CI and build Windows wheel for this version

## 0.1.2 - 2020-10-01

* Fix up WinRM wrapping on SSPI

## 0.1.1 - 2020-09-01

* Include the cython files in the built sdist

## 0.1.0 - 2020-07-22

Initial release of pyspnego

### 0.1.0rc4 - 2020-07-11

* Added the `wrap_winrm` and `unwrap_winrm` methods to a context to cover the complexity of WinRM wrapping
* Re-added `ContextReq.delegate_policy` and just make it optional based on the python-gssapi version installed

### 0.1.0rc3 - 2020-07-09

* Remove `ContextReq.delegate_policy` because [python-gssapi](https://github.com/pythongssapi/python-gssapi) does not support flags that they do not define

### 0.1.0rc2 - 2020-07-07

* Ensure any explicit Kerberos credentials have the `forwardable` flags set when `ContextReq.delegate` is requested
* Fix protocol check to use the options passed in by the caller

### 0.1.0rc1 - 2020-07-07

* Expanded `pyspnego-parse` help messages a bit more
* Added the `yaml` extras group to install `ruamel.yaml` which is an optional feature for `pyspengo-parse`

### 0.1.0b2 - 2020-07-05

* Fix context has been set up check on Windows initiator when running against localhost
* Ensure built wheels are not built with `linetrace=True` which breaks debugging in PyCharm

### 0.1.0b1 - 2020-07-04

First beta release of pyspnego.
