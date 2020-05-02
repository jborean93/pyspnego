# Python SPNEGO Library

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


## Changes required to ntlm-auth

* Fix up UNICODE flag to set in Negotiate
* Provide a way to see if a MIC has been set or not (`NtlmContext.mic_present`).
* Provide a way to sign/verify messages (`NtlmContext.verify(data, signature)` and `NtlmContext.sign(data)`)
* Provide a way to reset crypto state for both server and client (`NtlmContext.reset_rc4_state(sender=True)`)
