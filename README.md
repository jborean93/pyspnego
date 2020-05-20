# Python SPNEGO Library

[![Build Status](https://dev.azure.com/jborean93/jborean93/_apis/build/status/jborean93.pyspnego?branchName=master)](https://dev.azure.com/jborean93/jborean93/_build/latest?definitionId=2&branchName=master)
[![codecov](https://codecov.io/gh/jborean93/pyspnego/branch/master/graph/badge.svg)](https://codecov.io/gh/jborean93/pyspnego)

Library to handle SPNEGO (Negotiate, NTLM, Kerberos) authentication.

Still in progress.

## Test scenarios to complete

Need to test the following authentication exchanges against a Microsoft server.

* Raw NTLM
* Raw Kerberos
* NTLM through SPNEGO
* Kerberos through SPNEGO
* Kerberos encryption with the various encryption types
    * AES256-CTS-HMAC-SHA1-96
    * AES128-CTS-HMAC-SHA1-96
    * RC4-HMAC
    * RC4-HMAC-EXP
    * DES-CBC_MD5
    * DES-CBC-CRC

Would be nice to test the above against a Linux server as well

As a client we should also run the above scenarios against the following Kerberos versions

* Ubuntu 14.04
* MIT KRB5 v1.13.2 - Ubuntu 16.04
* Ubuntu 18.04
* Ubuntu 20.04
* EL7
* EL8
* Fedora 30
* Fedora 31
* Probably easier just testing KRB5 v1.13+ on all major versions
* Maybe also test as Heimdal as a client


## Debugging MIT krb5

```bash
cd /tmp
wget https://kerberos.org/dist/krb5/1.18/krb5-1.18.1.tar.gz
tar xf krb5-1.18.1.tar.gz
cd krb5-1.18.1/src
./configure CFLAGS=-g
make CFLAGS=-g
sudo make install DESTDIR=/opt/krb5-1.18.1

export PATH=/opt/krb5-1.18.1/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/opt/krb5-1.18.1/usr/local/lib:$LD_LIBRARY_PATH

cd /tmp
git clone git@github.com:gssapi/gss-ntlmssp.git
cd gss-ntlmssp

export CFLAGS="-I/opt/krb5-1.18.1/usr/local/include -g"
export LDFLAGS="-L/opt/krb5-1.18.1/usr/local/lib -Wl,-rpath=/opt/krb5-1.18.1/usr/local/lib"
autoreconf -f -i
./configure --prefix=/opt/gss-ntlmssp-0.8.0
make
sudo make install


echo "gssntlmssp_v1    1.3.6.1.4.1.311.2.2.10    /opt/gss-ntlmssp-0.8.0/lib/gssntlmssp/gssntlmssp.so" > /tmp/krb-mechs.conf
export GSS_MECH_CONFIG=/tmp/krb-mechs.conf


export GSSAPI_LINKER_ARGS="-L/opt/krb5-1.18.1/usr/local/lib -L/usr/local/lib -Wl,--enable-new-dtags -Wl,-rpath -Wl,/opt/krb5-1.18.1/usr/local/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
export GSSAPI_COMPILER_ARGS="-I/opt/krb5-1.18.1/usr/local/include -I/usr/local/include -DHAS_GSSAPI_EXT_H"
pip install gssapi --no-cache-dir
```


## Installing Heimdal on Centos 8

```bash
# On the host
docker run --rm -it centos:8 /bin/bash

# In the container
yum install -y epel-release
yum install -y \
  gcc \
  heimdal-devel \
  heimdal-libs \
  heimdal-path \
  heimdal-workstation \
  python3 \
  python3-devel \
  python3-pip \
  vim
source /etc/profile

cat > /etc/krb5.conf <<EOL
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
    default_realm = DOMAIN.LOCAL
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
  DOMAIN.LOCAL = {
    kdc = dc01.domain.local
    admin_server = dc01.domain.local
  }

[domain_realm]
  .domain.local = DOMAIN.LOCAL
  domain.local DOMAIN.LOCAL
EOL

pip3 install gssapi

echo "nameserver 192.168.56.10" > /etc/resolv.conf
```


# TODO List

* Look at optimising some of the large byte handling code by using `memory` view instead
* Tidy up `NTLMProxy`, especially around `usage='accept'`
* Try and simplify `pyspnego-parse` a bit more
* Test out channel bindings
* Unify exception handling
    * Exception code is in place, just need to try out the edge cases.
* Unify behaviour when accessing attributes like session_key when the context hasn't been established
* Tests, tests, and more tests
* As part of the tests, make `pyspnego.ps1` a bit more API like, expose each function in a request and return the result back to the caller for easier debugging
* Unify docstrings for public functions
* Maybe even look at a read the docs
* Create examples
* Once the format of `pyspnego-parse` has been finalised, redo the `scenarios` folder against the newer standards
* Test against `smbprotocol`
* Test against `requests-credssp`
* Test against `pypsrp`
* See if `pywinrm` wants to use this


## Exception details

This is trying to keep track of the various exceptions that can be fired by each proxy

Unmapped Windows errors:
* SEC_E_INSUFFICIENT_MEMORY
* SEC_E_INTERNAL_ERROR
* SEC_E_NOT_OWNER
* SEC_E_UNKNOWN_CREDENTIALS
* SEC_E_INVALID_HANDLE
* SEC_E_LOGON_DENIED - `RuntimeError: SSPI step failed: (-2146893044) SEC_E_LOGON_DENIED 0x8009030C - The logon attempt failed`
* SEC_E_NO_AUTHENTICATING_AUTHORITY
* SEC_E_WRONG_PRINCIPAL


Unmapped GSSAPI errors:
* GSS_S_BAD_NAMETYPE
* GSS_S_BAD_STATUS
* GSS_S_NO_CONTEXT
* GSS_S_DEFECTIVE_CREDENTIAL 
* GSS_S_CREDENTIALS_EXPIRED
* GSS_S_UNAUTHORIZED
* GSS_S_DUPLICATE_ELEMENT
* GSS_S_NAME_NOT_MN


```yaml
__init__():
  desired: |
    FeatureMissingError() done in base
    ValueError() done in base
    SpnegoError() with the following system exceptions
      BadMechanismError - When mech/protocol that isn't supported is specified.
      BadNameError - Invalid SPN

  base: |
    ValueError() for some invalid parameters
    FeatureMissingError() when NegotiateOptions specified cannot be guaranteed.
  sspi: |
    `AcquireCredentialsHandle()`:
      * SEC_E_INSUFFICIENT_MEMORY
      * SEC_E_INTERNAL_ERROR
      * SEC_E_NO_CREDENTIALS
      * SEC_E_NOT_OWNER
      * SEC_E_UNKNOWN_CREDENTIALS
    Can fail with memory allocation error but we probably don't need to worry about that.
    Have tested this out, can only get a failure with an invalid protocol specified. Others can probably happen but
    very edge case
  gssapi: |
    `gss_acquire_cred()` and `gss_acquire_cred_from_password()`:
      * BadNameTypeError - I don't think there is an analogue to SSPI, might keep generic
      * ExpiredCredentialsError
      * MissingCredentialsError
    
    Also creates the gssapi security context but this does not look like it actually makes any syscalls.
  negotiate: |
    Doesn't initialise anything, no errors expected
  ntlm: |
    For initiate, will get the credentials, either explicit or from the cache
    For accept, checks the cache is available

available_protocols():
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

iov_available:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

complete:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

context_attr:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

negotiated_protocol:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

session_key:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

step:
  desired:
  base:
  sspi:
  gssapi: |
    gss-ntlmssp specified invalid argument when the NT hash was not the same.
  negotiate:
  ntlm:

wrap:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

wrap_iov:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

unwrap:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

unwrap_iov:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

sign:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

verify:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

_context_attr_map:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

_requires_mech_list_mic:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

_create_spn:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

_convert_iov_buffer:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:

_reset_ntlm_crypto_state:
  desired:
  base:
  sspi:
  gssapi:
  negotiate:
  ntlm:
```

