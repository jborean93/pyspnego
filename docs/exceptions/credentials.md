# No cached credential

When trying to access the credential cache but no credential is present or the principal specified isn't in the cache
here are the errors that are returned.

## GSSAPI

To replicate this error run the following Python code. Make sure you have run `kdestroy`.

```python
#!/usr/bin/env python3
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

gssapi.Credentials(name=None, usage='initiate', mechs=[kerberos])
```

Output of the script on the various GSSAPI distributions

```bash
# Kerberos 5 release 1.17 - Centos 8
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529639053): No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_0)

# gss-ntlmssp - Centos 8
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (1314127894): Feature not available

# heimdal 7.7.0 - Centos 8
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (0): unknown mech-code 0 for mech unknown

# Kerberos 5 release 1.7-prerelease - macOS 10.15
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (0): unknown mech-code 0 for mech unknown
```

To replicate the error when an explicit principal was specified but doesn't exist in the cache run:

```python
#!/usr/bin/env python3
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

user = gssapi.Name('fake@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
gssapi.Credentials(name=user, usage='initiate', mechs=[kerberos])
```

```
# Kerberos 5 release 1.17 - Centos 8
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529639053): Can't find client principal fake@DOMAIN.LOCAL in cache collection

# heimdal 7.7.0 - Centos 8
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (0): unknown mech-code 0 for mech unknown

# Kerberos 5 release 1.7-prerelease - macOS 10.15
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (0): unknown mech-code 0 for mech unknown
```


# Invalid explicit password

Trying to get a credential with an invalid password.


## GSSAPI

```python
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('vagrant-domain@DOMAIN.LOCAL2', name_type=gssapi.NameType.user)
cred = gssapi.raw.acquire_cred_with_password(username, b'incorrect', usage='initiate', mechs=[kerberos])
```

Output

```
# Kerberos 5 release 1.18.1 - Fedora 32
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529638936): Preauthentication failed

# heimdal 7.7.9 - Centos 8
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (2529638936): Preauthentication failed
```


# Expired credential

Getting an expired credential from the credential cache.


## GSSAPI

Before running this you need to run `kinit -l 5 vagrant-domain@DOMAIN.LOCAL` and wait a few seconds.

```python
#!/usr/bin/env python3
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

cred = gssapi.Credentials(name=None, usage='initiate', mechs=[kerberos])
cred.lifetime
```

Output

```
# Kerberos 5 release 1.18.1 - Fedora 32
gssapi.raw.exceptions.ExpiredCredentialsError: Major (720896): The referenced credential has expired, Minor (100001): Unknown code 0

# heimdal 7.7.9 - Centos 8
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (0): unknown mech-code 0 for mech unknown
```

_Note: Heimdal actually fails when getting the credential and not when checking the lifetime._


# Realm unreachable

Trying to get a credential for a realm that isn't accessible

```python
import gssapi

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('vagrant-domain@FAKE.REALM', name_type=gssapi.NameType.user)
cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos])
```

Output

```
# Kerberos 5 release 1.18.1 - Fedora 32
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529639066): Cannot find KDC for realm "FAKE.REALM"

# heimdal 7.7.9 - Centos 8
gssapi.raw.exceptions.MissingCredentialsError: Major (458752):  No credentials were supplied, or the credentials were unavailable or inaccessible., Minor (2529639068): unable to reach any KDC in realm FAKE.REALM
```

_Note: This takes time to complete, might have implications for Negotiate authentication._
