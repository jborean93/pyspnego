# Known issues with GSSAPI

GSSAPI on Linux is typically provided by either the [MIT krb5](http://web.mit.edu/kerberos/) library or by
[Heimdal](https://github.com/heimdal/heimdal). While the behaviour of both are largely the same there can be some
differences in some edge cases. Pyspnego tries to iron out those differences where it can and make them the same but
in some cases that isn't possible. This document aims to outline all those behaviour differences and what pyspnego
tries to do about them.

_Note: The majority of the tests are done with MIT krb5 so that's the implementation that will work the best with pysnego._


# Scenarios

Each scenario below should outline

* The distribution/GSSAPI version that are known to be affected
* A description of the scenario
* The problem and known workarounds
* Python code that can be used to test out the scenario in the future

This is an evolving document and I'm trying to keep this updated as I figure out problems going forward.

* [Channel bindings on MIT Negotiate](#channel-bindings-on-mit-negotiate)
* [Delegation with explicit credentials](#delegation-with-explicit-credentials)
* [RC4 unwrapping on Heimdal](#rc4-unwrapping-on-heimdal)


## Channel bindings on MIT Negotiate

### Versions affects

| Distribution | MIT Version | Heimdal Version |
|-|-|-|
| Centos 8 | <=1.18.2 | N/A |

### Description

When using pure `SPNEGO` through MIT KRB5 it will fail to pass the channel bindings token along to the underlying
mech causing failures if CB were required by the acceptor. This has been fixed in a
[recent commit](https://github.com/krb5/krb5/commit/d16325a24c34ec9a5f6fb4910987f162e0d4d9cd) but not into any releases
as of yet. MIT KRB5's `SPNEGO` provider is only used when both Kerberos and NTLM are available, if it is not then
`pyspnego` will automatically use it's own Negotiate provider which handles this scenario just fine.

The workaround is to either set `options=spnego.NegotiateOptions.use_negotiate` to force the use of `pyspnego's`
Negotiate provider or set the protocol to either `ntlm` or `kerberos` explicitly.

### Code

This problem is already fixed and is just waiting on a new MIT KRB5 release, no need for code to test this.


## Delegation with explicit credentials

### Versions affected

| Distribution | MIT Version | Heimdal Version |
|-|-|-|
| Centos 8 | N/A | 7.7.0 |

### Description

When explicit credentials are used for Kerberos authentication there is no way to pass in desired flags into
`gss_acquire_cred_with_password`. For MIT we use a temporary `krb5.conf` file with the lines below to ensure that the
retrieved ticket is forwardable for delegation purposes:

```text
[libdefaults]
forwardable = true
```

Heimdal does not seem to use any of the `forwardable` flags in the `krb5.conf` so any credential that is retrieved
cannot be used in a delegation scenario. The only workaround is to call `kinit`, optionally with the `-f` flag, to
explicitly state that the credential can be forwarded/delegated. In pyspnego this means that no password should be set
when creating the context.

I have not tested this but it looks like [this PR](https://github.com/heimdal/heimdal/pull/738) will fix the problem
in Heimdal.

### Code

Before running this you must initialise the credential store by running `kinit -f username@REALM.COM`. You should also
make sure `[libdefaults]\nforwardable = true` is set in `/etc/krb5.conf`

```python
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')
username = gssapi.Name(base='username@REALM.COM', name_type=gssapi.NameType.user)
cred = gssapi.raw.acquire_cred_with_password(username, b'Password', usage='initiate', mechs=[kerberos]).creds
gssapi.raw.store_cred(cred, usage='initiate', mech=kerberos, overwrite=True)
```

Once that is complete run `klist -f` to view the cred store

```text
[vagrant@CENTOS8-HEIMDAL ~]$ klist -f
Credentials cache: FILE:/tmp/krb5cc_1000
        Principal: spnego@SPNEGO.TEST

  Issued                Expires             Flags    Principal
Jul 10 01:54:48 2020  Jul 10 11:54:48 2020  IA     krbtgt/SPNEGO.TEST@SPNEGO.TEST
```

The flags should contain `F` to indicate the credential is forwardable.


## RC4 unwrapping on Heimdal

### Versions affected

| Distribution | MIT Version | Heimdal Version |
|-|-|-|
| Centos 8 | N/A | 7.7.0 |

### Description

Heimdal's unwrapping code does not work the same way as MIT or SSPI. While the `unwrap_winrm()` function is designed
to paper over this problem as best as it can it doesn't fix the problem where RC4 wrapped data cannot be unwrapped when
using Heimdal. This shouldn't be an issue for most people but I am documenting it here in case someone comes across it
in the future.

There are 2 problems here;

* Heimdal mandates the presence of a `PADDING` IOV buffer in the call to `gss_unwrap_iov()`
* A bug in the RC4 decryption code which results in an erroneous validation error of the header

These 2 bugs have been fixed in [this PR](https://github.com/heimdal/heimdal/pull/740), the PR has also been tested and
confirmed to work using the same IOV buffer setup as both MIT and SSPI. Unfortunately using those IOV buffers fails
in existing Heimdal versions so the current code just calls `gss_unwrap()` which works only for AES. This unfortunately
means RC4 will never work until the code has changed to the IOV variant but that can only be done once the newer
Heimdal versions have a wider distribution.

### Code

This problem is being fixed in [the PR](https://github.com/heimdal/heimdal/pull/740) and this is extremely hard to
test. See [test_integration.py::test_winrm_rc4_wrapping](../tests/integration/templates/test_integration.py.tmpl) for
the integration test that covers this scenario. Currently it is disabled on the Heimdal tests.
