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

* [Delegation with explicit credentials](#delegation-with-explicit-credentials)


## Delegation with explicit credentials

### Versions affected

| Distribution | MIT Version | Heimdal Version |
|-|-|-|
| Centos 8 | - | 7.7.0 |

### Description

When explicit credentials are used for Kerberos authentication there is no way to pass in desired flags into
`gss_acquire_cred_with_password`. For MIT we use a temporary `krb5.conf` file with the lines below to ensure that the
retrieved ticket is forwardable for delegation purposes:

```text
[libdefaults]
forwardable = true
```

### Problem

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
