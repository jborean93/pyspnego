# Changelog

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
