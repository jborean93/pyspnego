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

## GSSAPI

