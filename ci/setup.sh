DEBIAN_FRONTEND=noninteractive
HOSTNAME=$(hostname)
REALM=$1

echo -e "127.0.0.1 $HOSTNAME.$REALM" >> /etc/hosts

echo "Installing system packages"
apt-get install -y \
  gcc \
  gss-ntlmssp \
  krb5-{user,kdc,admin-server,multidev} \
  libkrb5-dev \
  python-dev

echo "Creating /etc/krb5.conf"
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

echo "Creating new realm and realm permission for local use"
echo -e "*/*@${REALM^^}\t*" > /etc/krb5kdc/kadm5.acl
echo -e "password\npassword" | /usr/sbin/kdb5_util create -r ${REALM^^}

echo "Starting the KDC daemon"
/usr/sbin/krb5kdc
