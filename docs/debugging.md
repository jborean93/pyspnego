# Debugging Tips

A lot of behaviour in this authentication process relies on functions in the KRB5 system libraries. This page aims to
document how to create a debuggable build of MIT KRB5.


## Debugging MIT KRB5

```bash
cd /tmp
wget https://kerberos.org/dist/krb5/1.18/krb5-1.18.1.tar.gz
tar xf krb5-1.18.1.tar.gz
cd krb5-1.18.1/src
./configure CFLAGS=-g
make CFLAGS=-g
sudo make install DESTDIR=/opt/krb5

export PATH=/opt/krb5/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/opt/krb5/usr/local/lib:$LD_LIBRARY_PATH

cd /tmp
git clone git@github.com:gssapi/gss-ntlmssp.git
cd gss-ntlmssp

export CFLAGS="-I/opt/krb5/usr/local/include -g"
export LDFLAGS="-L/opt/krb5/usr/local/lib -Wl,-rpath=/opt/krb5/usr/local/lib"
autoreconf -f -i
./configure --prefix=/opt/gss-ntlmssp-0.8.0
make
sudo make install

echo "gssntlmssp_v1    1.3.6.1.4.1.311.2.2.10    /opt/gss-ntlmssp-0.8.0/lib/gssntlmssp/gssntlmssp.so" > /tmp/krb-mechs.conf
export GSS_MECH_CONFIG=/tmp/krb-mechs.conf

export GSSAPI_LINKER_ARGS="-L/opt/krb5/usr/local/lib -L/usr/local/lib -Wl,--enable-new-dtags -Wl,-rpath -Wl,/opt/krb5/usr/local/lib -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
export GSSAPI_COMPILER_ARGS="-I/opt/krb5/usr/local/include -I/usr/local/include -DHAS_GSSAPI_EXT_H"
pip install gssapi --no-cache-dir
```


## Debugging Heimdal KRb5

```bash
dnf install flex perl-JSON texinfo
autoreconf -f -i
./configure CFLAGS=-g --prefix=/opt/heimdal-7.7.0/ --disable-otp
make CFLAGS=-g
sudo make install

GSSAPI_LINKER_ARGS="-Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib64/heimdal -L/usr/lib64/heimdal -lgssapi"
GSSAPI_COMPILER_ARGS="-I/usr/include/heimdal"
GSSAPI_MAIN_LIB="/usr/lib64/heimdal/libgssapi.so"

git clone https://github.com/python-gssapi/python-gssapi.git
# Need to make sure we don't add gssapi_ext.h if MIT krb5 is also present
GSSAPI_LINKER_ARGS="$(/opt/heimdal-7.7.0/bin/krb5-config --libs gssapi)" GSSAPI_COMPILER_ARGS="$(/opt/heimdal-7.7.0/bin/krb5-config --cflags gssapi)" GSSAPI_MAIN_LIB="/opt/heimdal-7.7.0/lib/libgssapi.so" python setup.py bdist_wheel
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
