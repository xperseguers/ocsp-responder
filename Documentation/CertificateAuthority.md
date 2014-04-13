Creating and Using SSL Certificates
===================================

This tutorial shows how we may be our own root CA (Certificate Authority) so that we can take advantage of SSL
encryption without spending unnecessary money on having our certificates signed. It includes everything to have both
CRL and OCSP revocation in issued certificates.

A drawback is that browsers will still complain about our site not being trusted until our root certificate is imported.
However, once this is done, we are no different from the commercial root CAs.

Clients will only import our root certificate if they trust us. This is where the commercial CAs come in: they purport
to do extensive research into the people and organizations for whom they sign certificates. By importing (actually, by
the browser vendors incorporating) their trusted root certificates, we are saying that we trust them when they guarantee
that someone else is who they say they are. We can trust additional root CAs (like ourselves) by importing their CA
certificates.

Note: If you are in the business of running a commercial secure site, obtaining a commercially signed certificate is the
only realistic choice.


Initial Setup
-------------

First, we will create a directory where we can work. It does not matter where this is; I am arbitrarily going to create
it in my home directory.

	# mkdir CA
	# cd CA
	# mkdir newcerts private

The CA directory will contain:

- Our Certificate Authority (CA) certificate
- The database of the certificates that we have signed
- The keys, requests, and certificates we generate

It will also be our working directory when creating or signing certificates.

The ``CA/newcerts`` directory will contain:

- A copy of each certificate we sign

The ``CA/private`` directory will contain:

- Our CA private key

This key is important:

- Do not lose this key. Without it, you will not be able to sign or renew any certificates.
- Do not disclose this key to anyone. If it is compromised, others will be able to impersonate you.

Our next step is to create a database for the certificates we will sign:

	# echo '01' > serial
	# touch index.txt


Creating a Root Certificate
---------------------------

Rather than use the configuration file that comes with OpenSSL, we are going to create a minimal configuration of our
own in this directory. Start your editor (vi, pico, ...) and create ``openssl.cnf``:

	#
	# OpenSSL configuration file.
	#

	# Establish working directory.

	dir                          = .

	[ ca ]
	default_ca                   = CA_default

	[ CA_default ]
	serial                       = $dir/serial
	database                     = $dir/index.txt
	new_certs_dir                = $dir/newcerts
	certificate                  = $dir/cacert.pem
	private_key                  = $dir/private/cakey.pem
	x509_extensions              = usr_cert
	default_days                 = 730
	default_crl_days             = 30
	default_md                   = sha256
	preserve                     = no
	email_in_dn                  = no
	nameopt                      = default_ca
	certopt                      = default_ca
	policy                       = policy_match

	[ policy_match ]
	countryName                  = match
	stateOrProvinceName          = optional
	organizationName             = optional
	organizationalUnitName       = optional
	commonName                   = supplied
	emailAddress                 = optional

	[ req ]
	default_bits                 = 4096                  # Size of keys
	default_keyfile              = key.pem               # name of generated keys
	default_md                   = sha256                # message digest algorithm
	string_mask                  = nombstr               # permitted characters
	distinguished_name           = req_distinguished_name
	req_extensions               = v3_req

	[ req_distinguished_name ]
	# Variable name                Prompt string
	#---------------------------   ------------------------------
	0.organizationName           = Organization Name (company)
	organizationalUnitName       = Organizational Unit Name (department, division)
	emailAddress                 = Email Address
	emailAddress_max             = 40
	localityName                 = Locality Name (city, district)
	stateOrProvinceName          = State or Province Name (full name)
	countryName                  = Country Name (2 letter code)
	countryName_min              = 2
	countryName_max              = 2
	commonName                   = Common Name (hostname, IP, or your name)
	commonName_max               = 64

	# Default values for the above, for consistency and less typing.
	# Variable name                Value
	#---------------------------   ------------------------------
	0.organizationName_default   = My Sample Company
	localityName_default         = Fribourg
	stateOrProvinceName_default  = Fribourg
	countryName_default          = CH

	[ v3_ca ]
	basicConstraints             = CA:TRUE
	subjectKeyIdentifier         = hash
	authorityKeyIdentifier       = keyid:always,issuer:always

	[ v3_req ]
	basicConstraints             = CA:FALSE
	subjectKeyIdentifier         = hash

	[ crl_ext ]
	authorityKeyIdentifier       = keyid:always,issuer:always

	[ v3_OCSP ]
	basicConstraints             = CA:FALSE
	keyUsage                     = nonRepudiation, digitalSignature, keyEncipherment
	extendedKeyUsage             = OCSPSigning

	[ usr_cert ]
	basicConstraints             = CA:FALSE
	subjectKeyIdentifier         = hash
	authorityKeyIdentifier       = keyid,issuer:always
	authorityInfoAccess          = OCSP;URI:http://<uri to server>
	authorityInfoAccess          = caIssuers;URI:http://<uri to server>/ca.html
	nsCaRevocationUrl            = http://<uri to server>/revok.crl


In order to protect ourselves from unauthorized use of our CA certificate, it is passphrase protected. Each time you use
the CA certificate to sign a request, you will be prompted for the passphrase. Now would be a good time to pick a secure
passphrase and put it in a safe place.

All the preparation is now in place for creating our self-signed root certificate. For this, we want to override some of
the defaults we just put into the configuration, so we will specify our overrides on the command line.

Our overrides to the ``openssl req`` command are:

- Create a new self-signed certificate: ``-new -x509``
- Create a CA certificate: ``-extensions v3_ca``
- Make it valid for more than 30 days: ``-days 3650``
- Write output to specific locations: ``-keyout, -out``
- Use our configuration file: ``-config ./openssl.cnf``

_(A note on the term of validity of root certificates: When a root certificate expires, all of the certificates signed
with it are no longer valid. To correct this situation, a new root certificate must be created and distributed. Also,
all certificates signed with the expired one must be revoked, and re-signed with the new one. As this can be a lot of
work, you want to make your root certificate valid for as long as you think you will need it. In this example, we are
making it valid for ten years.)_

Run the command as shown. In this case, the PEM pass prhase it asks for is a new one, which you must enter twice:

	# openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem \
	-out cacert.pem -days 3650 -config ./openssl.cnf
	Generating a 4096 bit RSA private key
	..................................................................................................................++
	.................................................................++
	writing new private key to 'private/cakey.pem'
	Enter PEM pass phrase:
	Verifying - Enter PEM pass phrase:
	-----
	You are about to be asked to enter information that will be incorporated
	into your certificate request.
	What you are about to enter is what is called a Distinguished Name or a DN.
	There are quite a few fields but you can leave some blank
	For some fields there will be a default value,
	If you enter '.', the field will be left blank.
	-----
	Organization Name (company) [My Sample Company]:
	Organizational Unit Name (department, division) []:CA Division
	Email Address []:info@my-sample-company.ch
	Locality Name (city, district) [Fribourg]:
	State or Province Name (full name) [Fribourg]:
	Country Name (2 letter code) [CH]:
	Common Name (hostname, IP, or your name) []:MSC Root CA

This process produces two files as output:

- A private key in ``private/cakey.pem``
- A root CA certificate in ``cacert.pem``

``cacert.pem`` is the file you want to distribute to your clients.

We can query the contents of this certificate with openssl to learn to whom belongs, what it is valid for, etc.:

	# openssl x509 -in cacert.pem -noout -text
	# openssl x509 -in cacert.pem -noout -dates
	# openssl x509 -in cacert.pem -noout -purpose


Creating a Certificate Signing Request (CSR)
--------------------------------------------

Now that we have a root certificate, we can create any number of certificates for installation into our SSL applications
such as https, POP3s, or IMAPs. The procedure involves creating a private key and certificate request, and then signing
the request to generate the certificate.

The Common Name must be (or the IP address must resolve to) the server name your clients use to contact your host. If
this does not match, every time they connect your clients will get a message asking them if they want to use this
server. In effect, the client software is saying, "Warning! You asked for mail.sample.com; the responding machine's
certificate is for smtp.sample.com. Are you sure you want to continue?"

	# openssl req -new -nodes -out req.pem -config ./openssl.cnf
	...
	Organizational Unit Name (department, division) []:Mail Server
	Email Address []:postmaster@sample.com
	Common Name (hostname, IP, or your name) []:mail.sample.com
	...

This process produces two files as output:

- A private key in ``key.pem``
- A certificate signing request in ``req.pem``

These files should be kept. When the certificate you are about to create expires, the request can be used again to
create a new certificate with a new expiry date. The private key is of course necessary for SSL encryption. When you
save these files, meaningful names will help; for example, ``mailserver.key.pem`` and ``mailserver.req.pem``.

We can view the contents to make sure our request is correct:

	# openssl req -in req.pem -text -verify -noout | more


Signing a Certificate
---------------------

To sign the request we made in the previous step, execute the following and respond to the prompts. Note that you are
asked for the PEM passphrase selected earlier:

	# openssl ca -out cert.pem -config ./openssl.cnf -infiles req.pem
	Using configuration from ./openssl.cnf
	Enter pass phrase for ./private/cakey.pem:
	Check that the request matches the signature
	Signature ok
	The Subject's Distinguished Name is as follows
	organizationName      :PRINTABLE:'My Sample Company'
	organizationalUnitName:PRINTABLE:'Mail Server'
	localityName          :PRINTABLE:'Fribourg'
	stateOrProvinceName   :PRINTABLE:'Fribourg'
	countryName           :PRINTABLE:'CH'
	commonName            :PRINTABLE:'mail.sample.com'
	Certificate is to be certified until Apr 12 14:40:15 2016 GMT (730 days)
	Sign the certificate? [y/n]:y


	1 out of 1 certificate requests certified, commit? [y/n]y
	Write out database with 1 new entries
	Data Base Updated

This process updates the CA database, and produces two files as output:

- A certificate in ``cert.pem``
- A copy of the certificate in ``newcerts/<serial>.pem``

Again, you can inspect the certificate:

	# openssl x509 -in cert.pem -noout -text -purpose | more

The certificate has both the encoded version and a human-readable version in the same file. You can strip off the
human-readable portion as follows:

	# mv cert.pem tmp.pem
	# openssl x509 -in tmp.pem -out cert.pem

Some servers want a combined key and certificate file:

	# cat key.pem cert.pem > key-cert.pem


Revoking a Certificate
----------------------

The certificate is in the ``newcerts`` directory; you can determine its filename by browsing ``index.txt`` and searching
for the Common Name (CN) on it. The filename is the index plus the extension ``.pem``, for example ``02.pem``.

	# openssl ca -revoke newcerts/02.pem -config ./openssl.cnf
	Using configuration from ./openssl.cnf
	Enter PEM pass phrase:
	Revoking Certificate 02.
	Data Base Updated


Renewing Certificates
---------------------

Your certificate chain can break due to certificate expiry in two ways:

- The certificates you signed with your root certificate have expired.
- Your root certificate itself has expired.

In the second case, you have some work to do. A new root CA certificate must be created and distributed, and then your
existing certificates must be recreated or re-signed.

In the first case, you have two options. You can either generate new certificate signing requests and sign them as
described above, or (if you kept them) you can re-sign the original requests. In either case, the old certificates must
be revoked, and then the new certificates signed and installed into your secure applications as described earlier.

You cannot issue two certificates with the same Common Name, which is why the expired certificates must be revoked.

To revoke a certificate:

	# openssl ca -revoke newcerts/02.pem -config ./openssl.cnf
	Using configuration from ./openssl.cnf
	Enter PEM pass phrase:
	Revoking Certificate 02.
	Data Base Updated

Now that the certificate has been revoked, you can re-sign the original request, or create and sign a new one as
described above.

Sources:

- http://www.eclectica.ca/howto/ssl-cert-howto.php
- http://isrlabs.net/wordpress/?p=169