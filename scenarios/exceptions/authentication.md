# Bad password

## GSSAPI - NTLM

```python
import gssapi
import os
import tempfile

ntlm = gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10')


with tempfile.NamedTemporaryFile() as temp_fd:
    with open(temp_fd.name, mode='wb') as fd:
        fd.write(b'DOMAIN:USER:PASS')

    os.environ['NTLM_USER_FILE'] = temp_fd.name

    c_cred = gssapi.raw.acquire_cred_with_password(gssapi.Name('USER@DOMAIN', name_type=gssapi.NameType.user),
        b'invalid', usage='initiate', mechs=[ntlm]).creds
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate')
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')
    auth = c.step(s.step(c.step()))

    s.step(auth)
```

Outputs

```
# Kerberos 5 release 1.17 - gssnlmtssp 0.7.0
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (22): Invalid argument
```

_Note: Heimdal isn't used for NTLM because you cannot use acquire_cred_with_password._


# NTLM - Invalid MIC

```python
import gssapi
import os
import tempfile

ntlm = gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10')


with tempfile.NamedTemporaryFile() as temp_fd:
    with open(temp_fd.name, mode='wb') as fd:
        fd.write(b'DOMAIN:USER:PASS')

    os.environ['NTLM_USER_FILE'] = temp_fd.name

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate')
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    require_mic = gssapi.OID.from_int_seq('1.3.6.1.4.1.7165.655.1.2')

    nego = c.step()

    # Setting this here tells the client to set the MIC.
    gssapi.raw.inquire_sec_context_by_oid(c, require_mic)

    challenge = s.step(nego)
    auth = c.step(challenge)

    # Manually change the MIC to an invalid value
    auth = auth[:64] + (b"\x11" * 16) + auth[80:]

    s.step(auth)
```

Outputs

```
# Kerberos 5 release 1.17 - gssnlmtssp 0.7.0
gssapi.raw.exceptions.InvalidTokenError: Major (589824): Invalid token was supplied, Minor (13): Permission denied
```

_Note: Heimdal uses NTLMv1 auth which does not use a MIC, another reason why we don't use that for auth._


# Bad Channel Bindings

## GSSAPI - Kerberos

```python
import gssapi
import socket

from gssapi.raw import ChannelBindings


kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')
cbt1 = ChannelBindings(application_data=b"\x01")
cbt2 = ChannelBindings(application_data=b"\x02")

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate', channel_bindings=cbt1)
s = gssapi.SecurityContext(creds=s_cred, usage='accept', channel_bindings=cbt2)

token1 = c.step()
token2 = s.step(token1)  # Heimdal fails here
c.step(token2)  # MIT KRB5 fails here
```

Outputs

```
# Kerberos 5 release 1.17
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529638972): Generic error (see e-text)

# heimdal 7.7.0
gssapi.raw.exceptions.BadChannelBindingsError: Major (262144):  Incorrect channel bindings were supplied, Minor (0): Success
```

## GSSAPI - NTLM

```python
import gssapi
import os
import tempfile

from gssapi.raw import ChannelBindings

ntlm = gssapi.OID.from_int_seq('1.3.6.1.4.1.311.2.2.10')
cbt1 = ChannelBindings(application_data=b"\x01")
cbt2 = ChannelBindings(application_data=b"\x02")

with tempfile.NamedTemporaryFile() as temp_fd:
    with open(temp_fd.name, mode='wb') as fd:
        fd.write(b'DOMAIN:USER:PASS')

    os.environ['NTLM_USER_FILE'] = temp_fd.name

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate', channel_bindings=cbt1)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept', channel_bindings=cbt2)

    nego = c.step()
    challenge = s.step(nego)
    auth = c.step(challenge)
    s.step(auth)
```

Outputs

```
# Kerberos 5 release 1.17 - gssnlmtssp 0.7.0
gssapi.raw.exceptions.InvalidTokenError: Major (589824): Invalid token was supplied, Minor (13): Permission denied
```

## SSPI - Kerberos

```python
```

## SSPI - NTLM

```python
```

# Kerberos no mutual auth

By setting a flags and not with `mutual_authentication`, `c.step(token2)` will fail.

```python
import gssapi
import socket

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate', flags=gssapi.RequirementFlag.integrity)
s = gssapi.SecurityContext(creds=s_cred, usage='accept')

token1 = c.step()
token2 = s.step(token1)
c.step(token2)
```

Outputs

```
# Kerberos 5 release 1.17
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (39756036): Context is already fully established

# heimdal 7.7.0
gssapi.raw.exceptions.MalformedParameterError: Major (51183616): A parameter was malformed Miscellaneous failure (see text), Minor (0): Success
```
