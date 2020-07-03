# sign - no integrity

## Summary

* Doesn't fail as `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` is present in exchanges so a dummy signature is created
* `gss-ntlmssp` does have a [bug](https://github.com/gssapi/gss-ntlmssp/issues/19) where the dummy signature doesn't match SSPI.

TLDR: Don't check the flags, rely on the underlying mechanism to handle it.

## GSSAPI - Kerberos

```python
import gssapi
import socket

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate')
s = gssapi.SecurityContext(creds=s_cred, usage='accept')

c.step(s.step(c.step()))

enc = c.wrap(b"abc", True).message
s.unwrap(enc)
```

Works just fine on both MIT KRB5 and Heimdal. Looking at the source code it's actually hardcoding the integrity and
confidentiality flags so they will always be present.


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

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate', flags=gssapi.RequirementFlag.mutual_authentication)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    print(c.actual_flags)
    print(s.actual_flags)
    print(c.get_signature(b"abc"))
```

No failure, just `b"\x00" * 16`. The `integrity` flag must be set for a valid signature to be created, having just
`confidentiality` is not enough.


## SSPI - Kerberos

```python
from spnego._sspi_raw import *

import socket

spn = "host/%s" % socket.getfqdn()
context_req = ClientContextReq.mutual_auth
protocol = 'Kerberos'

auth_data = WinNTAuthIdentity(u'vagrant-domain@DOMAIN.LOCAL', None, u'VagrantPass1')

c_cred = acquire_credentials_handle(None, protocol, auth_data=auth_data, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

token1 = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=token1)
token1 = SecBufferDesc([SecBuffer(SecBufferType.token, token1[0].buffer)])

token2 = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, token1, context_req=context_req, output_buffer=token2)
token2 = SecBufferDesc([SecBuffer(SecBufferType.token, token2[0].buffer)])

final = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=token2,
                            output_buffer=final)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

data = b"abc"
sign = SecBufferDesc([
    SecBuffer(SecBufferType.data, data),
    SecBuffer(SecBufferType.token, length=sizes.max_signature),
])
make_signature(c_context, 0, sign, seq_no=0)
```

No failure


## SSPI - NTLM

```python
from spnego._sspi_raw import *

spn = ""
context_req = ClientContextReq.mutual_auth
protocol = 'NTLM'

c_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

nego = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=nego)
nego = SecBufferDesc([SecBuffer(SecBufferType.token, nego[0].buffer)])

challenge = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, nego, context_req=context_req, output_buffer=challenge)
challenge = SecBufferDesc([SecBuffer(SecBufferType.token, challenge[0].buffer)])

auth = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=challenge,
                            output_buffer=auth)
auth = SecBufferDesc([SecBuffer(SecBufferType.token, auth[0].buffer)])

out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, auth, context_req=context_req, output_buffer=out_buffer)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

data = b"abc"
sign = SecBufferDesc([
    SecBuffer(SecBufferType.data, data),
    SecBuffer(SecBufferType.token, length=sizes.max_signature),
])
make_signature(c_context, 0, sign, seq_no=0)
```

No failure


# wrap - no confidentiality

## Summary

* The underlying context should handle it
* For NTLMProxy we should fail when neither flags are set but continue if either `integrity` or `confidentiality` are set

## GSSAPI - Kerberos

See `sign - no integrity`, no error occurs.


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

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate', flags=gssapi.RequirementFlag.mutual_authentication)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    print(c.actual_flags)
    print(s.actual_flags)

    enc = c.wrap(b"abc", True).message

    s.unwrap(enc)
```

This seg faults on all current releases but has been fixed in master with https://github.com/gssapi/gss-ntlmssp/pull/18.
The output from that is

```
gssapi.raw.misc.GSSError: Major (851968): Unspecified GSS failure. Minor code may provide more information, Minor (95): Operation not supported
```

If I add `integrity` then it works just fine, it seems like either the flags need to be set for this to work.


## SSPI - Kerberos

```python
from spnego._sspi_raw import *

import socket

spn = "host/%s" % socket.getfqdn()
context_req = ClientContextReq.mutual_auth
protocol = 'Kerberos'

auth_data = WinNTAuthIdentity(u'vagrant-domain@DOMAIN.LOCAL', None, u'VagrantPass1')

c_cred = acquire_credentials_handle(None, protocol, auth_data=auth_data, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

token1 = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=token1)
token1 = SecBufferDesc([SecBuffer(SecBufferType.token, token1[0].buffer)])

token2 = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, token1, context_req=context_req, output_buffer=token2)
token2 = SecBufferDesc([SecBuffer(SecBufferType.token, token2[0].buffer)])

final = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=token2,
                            output_buffer=final)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov, seq_no=0, qop=51566)
```

Outputs

```
OSError: [WinError -2146893054] The function requested is not supported
```

_Note: Must have confidentiality, integrity is not enough._


## SSPI - NTLM

```python
from spnego._sspi_raw import *

spn = ""
context_req = ClientContextReq.mutual_auth
protocol = 'NTLM'

c_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

nego = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=nego)
nego = SecBufferDesc([SecBuffer(SecBufferType.token, nego[0].buffer)])

challenge = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, nego, context_req=context_req, output_buffer=challenge)
challenge = SecBufferDesc([SecBuffer(SecBufferType.token, challenge[0].buffer)])

auth = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=challenge,
                            output_buffer=auth)
auth = SecBufferDesc([SecBuffer(SecBufferType.token, auth[0].buffer)])

out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, auth, context_req=context_req, output_buffer=out_buffer)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov, seq_no=0, qop=0)
```

Outputs

```
OSError: [WinError -2146893054] The function requested is not supported
```

_Note: if either integrity or confidentiality is set this works._


# wrap - invalid qop

## Summary

* The only provider that validates the QoP is MIT KRB5 and gss-ntlmssp.
* The NTLMProxy should just be strict in case someone implicitly relies on a QoP that we don't know about.


## GSSAPI - Kerberos

```python
import gssapi
import socket

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate')
s = gssapi.SecurityContext(creds=s_cred, usage='accept')

c.step(s.step(c.step()))

gssapi.raw.wrap(c, b"abc", True, 1024)
```

Heimdal does not complain but MIT KRB5 fails with

```
# Kerberos 5 release 1.17
gssapi.raw.exceptions.BadQoPError: Major (917504): The quality-of-protection (QOP) requested could not be provided, Minor (2249944328): Unknown quality of protection specified
```

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

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate', flags=gssapi.RequirementFlag.confidentiality)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    gssapi.raw.wrap(c, b"abc", True, 1024)
```

Outputs

```
# Kerberos 5 release 1.17 - gssntlmssp 0.7.0
gssapi.raw.exceptions.BadQoPError: Major (917504): The quality-of-protection (QOP) requested could not be provided, Minor (1314127877): Invalid value in argument
```

## SSPI - Kerberos

```python
from spnego._sspi_raw import *

import socket

spn = "host/%s" % socket.getfqdn()
context_req = ClientContextReq.integrity | ClientContextReq.confidentiality | ClientContextReq.mutual_auth
protocol = 'Kerberos'

auth_data = WinNTAuthIdentity(u'vagrant-domain@DOMAIN.LOCAL', None, u'VagrantPass1')

c_cred = acquire_credentials_handle(None, protocol, auth_data=auth_data, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

token1 = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=token1)
token1 = SecBufferDesc([SecBuffer(SecBufferType.token, token1[0].buffer)])

token2 = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, token1, context_req=context_req, output_buffer=token2)
token2 = SecBufferDesc([SecBuffer(SecBufferType.token, token2[0].buffer)])

final = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=token2,
                            output_buffer=final)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov, seq_no=0, qop=51566)
```

Doesn't fail.


## SSPI - NTLM

```python
from spnego._sspi_raw import *

spn = ""
context_req = ClientContextReq.mutual_auth | ClientContextReq.confidentiality | ClientContextReq.integrity
protocol = 'NTLM'

c_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

nego = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=nego)
nego = SecBufferDesc([SecBuffer(SecBufferType.token, nego[0].buffer)])

challenge = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, nego, context_req=context_req, output_buffer=challenge)
challenge = SecBufferDesc([SecBuffer(SecBufferType.token, challenge[0].buffer)])

auth = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=challenge,
                            output_buffer=auth)
auth = SecBufferDesc([SecBuffer(SecBufferType.token, auth[0].buffer)])

out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, auth, context_req=context_req, output_buffer=out_buffer)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov, seq_no=0, qop=51566)
```

Doesn't fail


# sign - invalid qop

## Summary

* The only provider that validates the QoP is MIT KRB5 and gss-ntlmssp.
* The NTLMProxy should just be strict in case someone implicitly relies on a QoP that we don't know about.

## GSSAPI - Kerberos

```python
import gssapi
import socket

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate')
s = gssapi.SecurityContext(creds=s_cred, usage='accept')

c.step(s.step(c.step()))

gssapi.raw.get_mic(c, b"abc", 1024)
```

Heimdal does not complain but MIT KRB5 fails with

```
# Kerberos 5 release 1.17
gssapi.raw.exceptions.BadQoPError: Major (917504): The quality-of-protection (QOP) requested could not be provided, Minor (2249944328): Unknown quality of protection specified
```

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

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate', flags=gssapi.RequirementFlag.confidentiality)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    gssapi.raw.get_mic(c, b"abc", 1024)
```

Outputs

```
# Kerberos 5 release 1.17 - gssntlmssp 0.7.0
gssapi.raw.exceptions.BadQoPError: Major (917504): The quality-of-protection (QOP) requested could not be provided, Minor (1314127877): Invalid value in argument
```

## SSPI - Kerberos and NTLM

```python
from spnego._sspi_raw import *

import socket

spn = "host/%s" % socket.getfqdn()
context_req = ClientContextReq.integrity | ClientContextReq.confidentiality | ClientContextReq.mutual_auth
protocol = 'Kerberos'

auth_data = WinNTAuthIdentity(u'vagrant-domain@DOMAIN.LOCAL', None, u'VagrantPass1')

c_cred = acquire_credentials_handle(None, protocol, auth_data=auth_data, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

token1 = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=token1)
token1 = SecBufferDesc([SecBuffer(SecBufferType.token, token1[0].buffer)])

token2 = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, token1, context_req=context_req, output_buffer=token2)
token2 = SecBufferDesc([SecBuffer(SecBufferType.token, token2[0].buffer)])

final = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=token2,
                            output_buffer=final)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

data = b"abc"
sign = SecBufferDesc([
    SecBuffer(SecBufferType.data, data),
    SecBuffer(SecBufferType.token, length=sizes.max_signature),
])
make_signature(c_context, 10, sign, seq_no=0)
```

SSPI doesn't seem to care about the QoP.


# NTLM - wrap_iov

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
                               creds=c_cred, mech=ntlm, usage='initiate', flags=gssapi.RequirementFlag.confidentiality)
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    iov = gssapi.raw.IOV(gssapi.raw.IOVBufferType.header, b"abc", gssapi.raw.IOVBufferType.padding, std_layout=False)
    gssapi.raw.wrap_iov(c, iov, True, 0)
```

Outputs

```
# Kerberos 5 release 1.17 - gssntlmssp 0.7.0
gssapi.raw.exceptions.OperationUnavailableError: Major (1048576): The operation or option is not available or unsupported, Minor (0): Unknown error
```

This is expected as gssntlmssp does not offer IOV buffers for it's NTLM implementation.


# Out of sequence wrapping

## Summary

* Only Kerberos seems to check the sequence number
* NTLM just verifies the signature but doesn't error when out of sequence.


## GSSAPI - Kerberos

```python
import gssapi
import socket

kerberos = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')

username = gssapi.Name('admin@DOMAIN.LOCAL', name_type=gssapi.NameType.user)
c_cred = gssapi.raw.acquire_cred_with_password(username, b'password', usage='initiate', mechs=[kerberos]).creds
s_cred = gssapi.Credentials(usage='accept', mechs=[kerberos])

c = gssapi.SecurityContext(name=gssapi.Name('host@%s' % socket.gethostname(), name_type=gssapi.NameType.hostbased_service),
                           creds=c_cred, mech=kerberos, usage='initiate')
s = gssapi.SecurityContext(creds=s_cred, usage='accept')

c.step(s.step(c.step()))

enc1 = c.wrap(b"abc", True).message
enc2 = c.wrap(b"def", True).message

s.unwrap(enc2)
```

Outputs

```
# Kerberos 5 release 1.17
gssapi.raw.exceptions.TokenTooEarlyError: Major (16): An expected per-message token was not received, Minor (100001): Success

# heimdal 7.7.0
gssapi.raw.exceptions.TokenTooEarlyError: Major (16): unknown routine error, Minor (0): unknown mech-code 0 for mech unknown
```


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

    c_cred = gssapi.Credentials(usage='initiate', mechs=[ntlm])
    s_cred = gssapi.Credentials(usage='accept', mechs=[ntlm])

    c = gssapi.SecurityContext(name=gssapi.Name('http@test', name_type=gssapi.NameType.hostbased_service),
                               creds=c_cred, mech=ntlm, usage='initiate')
    s = gssapi.SecurityContext(creds=s_cred, usage='accept')

    s.step(c.step(s.step(c.step())))

    enc1 = c.wrap(b"abc", True).message
    enc2 = c.wrap(b"def", True).message

    s.unwrap(enc2)
```

Outputs

```
# Kerberos 5 release 1.17 - gssnlmtssp 0.7.0
gssapi.raw.exceptions.BadMICError: Major (393216): A token had an invalid Message Integrity Check (MIC), Minor (100005): Unknown Error
```


## SSPI - Kerberos

This must be run as the `SYSTEM` account to be able to accept SPN's under `host` for the computer account.

```python
from spnego._sspi_raw import *

import socket

spn = "host/%s" % socket.getfqdn()
context_req = ClientContextReq.integrity | ClientContextReq.confidentiality | ClientContextReq.mutual_auth
protocol = 'Kerberos'

auth_data = WinNTAuthIdentity(u'vagrant-domain@DOMAIN.LOCAL', None, u'VagrantPass1')

c_cred = acquire_credentials_handle(None, protocol, auth_data=auth_data, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

token1 = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=token1)
token1 = SecBufferDesc([SecBuffer(SecBufferType.token, token1[0].buffer)])

token2 = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, token1, context_req=context_req, output_buffer=token2)
token2 = SecBufferDesc([SecBuffer(SecBufferType.token, token2[0].buffer)])

final = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=token2,
                            output_buffer=final)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov1 = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov1, seq_no=0, qop=0)

iov2 = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov2, seq_no=0, qop=0)

decrypt_message(s_context, iov2, seq_no=0)
```

Outputs

```
# Server 2019
OSError: [WinError -2146893040] The message supplied for verification is out of sequence
```

## SSPI - NTLM

```python
from spnego._sspi_raw import *

spn = ""
context_req = ClientContextReq.integrity | ClientContextReq.confidentiality
protocol = 'NTLM'

c_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.outbound)
s_cred = acquire_credentials_handle(None, protocol, credential_use=CredentialUse.inbound)

c_context = SecurityContext()
s_context = SecurityContext()

nego = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, output_buffer=nego)
nego = SecBufferDesc([SecBuffer(SecBufferType.token, nego[0].buffer)])

challenge = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, nego, context_req=context_req, output_buffer=challenge)
challenge = SecBufferDesc([SecBuffer(SecBufferType.token, challenge[0].buffer)])

auth = SecBufferDesc([SecBuffer(SecBufferType.token)])
initialize_security_context(c_cred, c_context, spn, context_req=context_req, input_buffer=challenge,
                            output_buffer=auth)
auth = SecBufferDesc([SecBuffer(SecBufferType.token, auth[0].buffer)])

out_buffer = SecBufferDesc([SecBuffer(SecBufferType.token)])
accept_security_context(s_cred, s_context, auth, context_req=context_req, output_buffer=out_buffer)

sizes = query_context_attributes(c_context, SecPkgAttr.sizes)

iov1 = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov1, seq_no=0, qop=0)

iov2 = SecBufferDesc([
    SecBuffer(SecBufferType.token, length=sizes.security_trailer),
    SecBuffer(SecBufferType.data, b"Hello world"),
    SecBuffer(SecBufferType.padding, length=sizes.block_size),
])
encrypt_message(c_context, iov2, seq_no=0, qop=0)

decrypt_message(s_context, iov2, seq_no=0)
```

Outputs

```
# Server 2019
OSError: [WinError -2146893041] The message or signature supplied for verification has been altered
```
