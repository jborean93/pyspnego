# Debugging Tips

A lot of behaviour in this authentication process relies on functions in the KRB5 system libraries. This page aims to
document how to create a debuggable build of MIT KRB5.


## Debugging MIT KRB5

```bash
# docker run --rm -it fedora:34 /bin/bash

dnf install -y \
  autoconf \
  automake \
  byacc \
  diffutils \
  findutils \
  gcc \
  gettext \
  git \
  libtool \
  libunistring-devel \
  make \
  openssl-devel \
  python \
  python-devel \
  python-pip \
  zlib-devel

pushd /tmp
git clone https://github.com/krb5/krb5.git

pushd krb5/src
autoreconf -f -i
./configure CFLAGS=-g
make CFLAGS=-g
make install DESTDIR=/opt/krb5-src

export PATH=/opt/krb5-src/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/opt/krb5-src/usr/local/lib:$LD_LIBRARY_PATH

popd

git clone https://github.com/gssapi/gss-ntlmssp.git
pushd gss-ntlmssp

autoreconf -f -i

CFLAGS="-I/opt/krb5-src/usr/local/include -g" \
  LDFLAGS="-L/opt/krb5-src/usr/local/lib -Wl,-rpath=/opt/krb5-src/usr/local/lib" \
  ./configure \
  --prefix=/opt/gss-ntlmssp \
  --with-wbclient=no \
  --with-manpages=no

echo "gssntlmssp_v1    1.3.6.1.4.1.311.2.2.10    /opt/gss-ntlmssp/lib/gssntlmssp/gssntlmssp.so" > /tmp/krb-mechs.conf
export GSS_MECH_CONFIG=/tmp/krb-mechs.conf

git clone https://github.com/pythongssapi/python-gssapi.git
pushd python-gssapi

pip install Cython wheel
GSSAPI_LINKER_ARGS="-L/opt/krb5-src/usr/local/lib -L/usr/local/lib -Wl,--enable-new-dtags -Wl,-rpath -Wl,/opt/krb5-src/usr/local/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err" \
  GSSAPI_COMPILER_ARGS="-I/opt/krb5-src/usr/local/include -I/usr/local/include -DHAS_GSSAPI_EXT_H" \
  python setup.py bdist_wheel
  
pip install dist/gssapi-*.whl

popd
popd
```


## Debugging Heimdal KRb5

```bash
# docker run --rm -it fedora:34 /bin/bash

dnf install -y \
  autoconf \
  automake \
  byacc \
  flex \
  libtool \
  make \
  ncurses-devel \
  perl-JSON \
  python \
  python-devel \
  python-pip \
  texinfo \
  git

pushd /tmp
git clone https://github.com/heimdal/heimdal.git

pushd heimdal
autoreconf -f -i
./configure CFLAGS=-g --prefix="/opt/heimdal-src" --disable-otp

# https://github.com/heimdal/heimdal/issues/794
cp ./lib/libedit/src/vis.h include/

make CFLAGS=-g
make install
popd

git clone https://github.com/pythongssapi/python-gssapi.git
pushd python-gssapi

pip install Cython wheel
GSSAPI_LINKER_ARGS="$(/opt/heimdal-src/bin/krb5-config --libs gssapi)" \
  GSSAPI_COMPILER_ARGS="$(/opt/heimdal-src/bin/krb5-config --cflags gssapi)" \
  GSSAPI_MAIN_LIB="/opt/heimdal-src/lib/libgssapi.so" \
  python setup.py bdist_wheel
pip install dist/gssapi-*.whl

popd
popd
```

## Setting up Linux KDC

Here are some commands to run to set up a KDC inside a docker container. This is mostly just a way to test out various
scenarios against the different packages. The username created is `admin@DOMAIN.LOCAL` with the password `password`.

### MIT KRB5

```bash
HOSTNAME=$(hostname)
REALM=domain.local
USERNAME=admin
PASSWORD=password

yum install -y epel-release
yum install -y \
  gcc \
  gssntlmssp \
  krb5-devel \
  krb5-server \
  krb5-workstation \
  python3 \
  python3-devel \
  python3-pip \
  vim

echo -e "127.0.0.1\t$HOSTNAME.$REALM" >> /etc/hosts

cat > /etc/krb5.conf <<EOL
[libdefaults]
  default_realm = ${REALM^^}
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  ${REALM^^} = {
    kdc = ${HOSTNAME,,}.${REALM,,}
    admin_server = ${HOSTNAME,,}.${REALM,,}
  }

[domain_realm]
  .${REALM,,} = ${REALM^^}
  ${REALM,,} = ${REALM^^}
EOL

echo -e "*/*@${REALM^^}\t*" > /var/kerberos/krb5kdc/kadm5.acl

# Create the new realm
echo -e "$PASSWORD\n$PASSWORD" | /usr/sbin/kdb5_util create -r ${REALM^^}

# Create the user principal
kadmin.local -q "addprinc -pw $PASSWORD $USERNAME"

# Create the SPNs and add it to the /etc/krb5.keytab
kadmin.local -q "addprinc -randkey host/$HOSTNAME@${REALM^^}"
kadmin.local -q "ktadd -k /etc/krb5.keytab host/$HOSTNAME@${REALM^^}"

kadmin.local -q "addprinc -randkey host/${HOSTNAME^^}@${REALM^^}"
kadmin.local -q "ktadd -k /etc/krb5.keytab host/${HOSTNAME^^}@${REALM^^}"

# Start the KDC service
/usr/sbin/krb5kdc

pip3 install gssapi
```

### Heimdal

```bash
HOSTNAME=$(hostname)
REALM=domain.local
USERNAME=admin
PASSWORD=password

yum install -y epel-release
yum install -y \
  gcc \
  heimdal-devel \
  heimdal-libs \
  heimdal-path \
  heimdal-server \
  heimdal-workstation \
  python3 \
  python3-devel \
  python3-pip \
  vim
source /etc/profile  # Ensure the Heimdal binaries are in the PATH

echo -e "127.0.0.1\t$HOSTNAME.$REALM" >> /etc/hosts

cat > /etc/krb5.conf <<EOL
[libdefaults]
  default_realm = ${REALM^^}
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  ${REALM^^} = {
    kdc = ${HOSTNAME,,}.${REALM,,}
    admin_server = ${HOSTNAME,,}.${REALM,,}
  }

[domain_realm]
  .${REALM,,} = ${REALM^^}
  ${REALM,,} = ${REALM^^}
EOL

echo -e "*/*@${REALM^^}\t*" > /var/heimdal/kadmind.acl

# Create the new realm
echo -e "\n\n" | kadmin -l init ${REALM^^}

# Create the user principal
kadmin -l add --use-defaults --password=$PASSWORD $USERNAME

# Create the SPNs and add it to the /etc/krb5.keytab
kadmin -l add --random-key --use-defaults host/$HOSTNAME@${REALM^^}
kadmin -l ext --keytab=/etc/krb5.keytab host/$HOSTNAME@${REALM^^}

kadmin -l add --random-key --use-defaults host/${HOSTNAME^^}@${REALM^^}
kadmin -l ext --keytab=/etc/krb5.keytab host/${HOSTNAME^^}@${REALM^^}

# Start the KDC service
/usr/libexec/kdc --detach

pip3 install gssapi
```
