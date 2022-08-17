# Changelog

## 0.6.0 - 2022-08-18

* Drop support for Python 3.6 - new minimum is 3.7+
* Moved setuptools config into `pyproject.toml` and made `Cython` a build requirement for Windows
  * For most users this is a hidden change
  * If a tool follows the PEP 517 standard, like pip, this build dependency will work automatically
  * The pre cythonised files are no longer included in the sdist going forward


## 0.5.4 - 2022-08-11

* Fix str of enum values when running in Python 3.11 to be consistent with older versions
* Support `gssapi` on 1.5.x which comes with RHEL 8.


## 0.5.3 - 2022-07-11

* Fix heap allocation errors when running with heap allocation monitoring on Windows


## 0.5.2 - 2022-04-29

* Added custom MD4 hashing code for NTLM to use.
  * Newer Linux distributions ship with OpenSSL 3.x which typically disables MD4 breaking the use of `hashlib.new('md4', b"")`
  * Using this custom code allows NTLM to continue to work
  * While it's bad to continue to use older hashing mechanisms in this case there is no valid alternative available


## 0.5.1 - 2022-03-21

* Call `gss_inquire_sec_context_by_oid(ctx, spnego_req_mechlistMIC_oid)` when using pure NTLM over GSSAPI to ensure the token contains a MIC


## 0.5.0 - 2022-02-21

* Added the `auth_stage` extra_info for a CredSSP context to give a human friendly indication of what sub auth stage it is up to.
* Added the `protocol_version` extra_info for a CredSSP context to return the negotiated CredSSP protocol version.
* Added the `credssp_min_protocol` keyword argument for a CredSSP context to set a minimum version the caller will accept of the peer.
  * This can be set to `5+` to ensure the peer supports and applies the mitigations for CVE-2018-0886.
* Added safeguards when trying to retrieve the completed context attributes of `NegotiateProxy` before any contexts have been set up (https://github.com/jborean93/pyspnego/issues/33)


## 0.4.0 - 2022-02-16

### Features

* Add `usage` argument for `tls.default_tls_context` to control whether the context is for a initiator or acceptor
* Add type annotations and include `py.typed` in the package for downstream library use
* Expose the `ContextProxy` class for type annotation use
* Added `get_extra_info` to `ContextProxy` to expose a common way to retrieve context specific information, this is currently used by CredSSP to retrieve
  * `client_credential`: The delegated client credential for acceptors once the context is complete
  * `sslcontext`: The SSL context used to create the TLS object
  * `ssl_object`: The TLS object used during the CredSSP exchange
* The `client_credential` property on `CredSSP` has been removed in favour of `context.get_extra_info('client_credential')
* Added support for custom credential types
  * Can be used to for things like NTLM authentication with NT/LM hashes, Kerberos with a keytab or from an explicit CCache, etc
* Support calling SSPI through `pyspnego`'s Negotiate proxy context
  * This allows users on Windows to still use Negotiate auth but with a complex set of credentials
  * Also opens up the ability to use Negotiate but only with Kerberos auth

### Deprecations

* The `username` and `password` property on the auth context object are deprecated and will return `None` until it is removed in a future release


## 0.3.1 - 2021-10-29

* Do not convert GSSAPI service to lowercase for GSSAPI and uppercase for SSPI
  * SPNs are case insensitive on Windows but case sensitive on Linux
  * Convering the service portion to upper or lower case could cause problems finding the target server on non-Windows GSSAPI implementations


## 0.3.0 - 2021-10-19

### Packaging Changes

* Changed project structure to a `src` layout
* Include both Cython `pyx/pyd` and `C` files for SSPI in the sdist generated
* Added Python 3.10 wheel

### Bugfixes

* Ensure bad SPNEGO token inputs are raised as `InvalidTokenError` rather than `struct.error`


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
