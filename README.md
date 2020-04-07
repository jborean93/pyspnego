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
