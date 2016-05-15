# Check_SSL
App with simple GUI to check SSL certificate details in a range of IPs.

Live version: http://hasi.usermd.net/ssl_test/

Python 3.5

Django 1.9

pyOpenSSL, netaddr

Input examples:

CIDR: [ 216.58.209.0/31, 216.58.209.10/30 ]

Range of IPs: [ 216.58.209.0-216.58.209.22 ]

Output:

IP, Subject, Issuer, Signature Algorithm, Valid from/until, Alternative names.
