# No cached credential error info

When trying to access the credential cache but no credential is present here are the errors that are returned

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

Ultimately it looks like MIT krb5 and Heimdal won't easily match up, we could potentially look at the minor codes


## SSPI

Run the following Python code.

```python

```