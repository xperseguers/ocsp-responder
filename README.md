ocsp-responder
==============

This OCSP responder operates from pre-produced set of OCSP responses. The responder is light-weight, does not require
signing key handling. It simply serves files from a disk.


Requirements
------------

* Any HTTP server suitable for running PHP scripts (tested with Apache 2.2)
* PHP version 5.3 or higher


Source
------

This project is based on libpkix-asn1-php_1.0-6_all.deb available on http://pki.cesnet.cz/sw/ocsp
