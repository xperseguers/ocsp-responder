How to set up OCSP using OpenSSL
================================

Assuming that you already have an OpenSSL Certificate Authority set up, you will need to make a couple of changes to your openssl.cnf file. Add a new line to the usr_cert stanza

	[ usr_cert ]
	authorityInfoAccess = OCSP;URI:http://<uri to server>

create a new stanza

	[ v3_OCSP ]
	basicConstraints = CA:FALSE
	keyUsage = nonRepudiation, digitalSignature, keyEncipherment
	extendedKeyUsage = OCSPSigning

For this example, the OCSP server will be running on ca.isrlabs.net on port 8888, so the authorityInfoAccess line will look like:

	authorityInfoAccess = OCSP;URI:http://ca.isrlabs.net:8888

This line will add a new attribute to issued certs that tells clients where the CA’s OCSP server is located so it can check the validity of the cert. The new v3 template assigns a neccesary attribute “OCSPSigning” to any certificate issued under this template. We will need to issue an OCSP signing certificate to the OCSP server with the OCSPSigning attribute, otherwise signature verification will fail when a cert is being checked. This is the first thing we will do:

	openssl req -new -nodes -out ca.isrlabs.net.csr -keyout ca.isrlabs.net.key -extensions v3_OCSP

Sign the request with the CA signing key:

	openssl ca -in auth.isrlabs.net.csr -out auth.isrlabs.net.crt -extensions v3_OCSP

OpenSSL should show the signing request, look for this in the X509v3 extensions:

	X509v3 Extended Key Usage:
	OCSP Signing

Sign and commit the request. Now, issue a throwaway cert and sign it

	openssl req -new -nodes -out dummy.isrlabs.net.csr -keyout dummy.isrlabs.net.key
	openssl ca -in dummy.isrlabs.net.csr -out dummy.isrlabs.net.crt

Next, start up the OCSP server.

	openssl ocsp -index /etc/pki/CA/index.txt -port 8888 -rsigner ca.isrlabs.net.crt -rkey ca.isrlabs.net.key -CA /etc/pki/CA/cacert.pem -text -out log.txt

Once the dummy cert has been been issued and the OCSP server started, we can test the cert using the “openssl ocsp” command. To verify a certificate with OpenSSL, the command syntax is:

	openssl ocsp -CAfile <cafile pem> -issuer <issuing ca pem> -cert <certificate to check> -url <url to OCSP server> -resp_text

So to test our dummy file:

	openssl ocsp -CAfile cacert.pem -issuer cacert.pem -cert dummy.isrlabs.net.crt -url http://ca.isrlabs.net:8888 -resp_text

There’s going to be a large block of text flooding the screen. Some of the more important text:

	OCSP Response Data:
	OCSP Response Status: successful (0×0)
	Response Type: Basic OCSP Response
	…
	Certificate ID:
	Hash Algorithm: sha1
	Issuer Name Hash: 922CD93C975EDC121DB25B1A55BA9B544E06F9B3
	Issuer Key Hash: 322A8DBF79BE1A934543DC4F24FC69220A2803BA
	Serial Number: 06
	Cert Status: good
	…
	Response verify OK
	dummy.isrlabs.net.crt: good
	This Update: Feb 27 00:55:54 2012 GMT

Now revoke the cert, regenerate the CRL and restart the OCSP server (the server must be restarted every time a cert is issued or revoked). If the OCSP signing certificate was not issued with the OCSPSigning attribute, OpenSSL will gripe that the verification did not work properly. Reissue the signing cert with the OCSPSigning attribute for the server.

	openssl ca -revoke /etc/pki/CA/newcerts/06.pem
	openssl ca -gencrl -out /etc/pki/CA/crl.pem

Now we can verify the certificate again:

	openssl ocsp -CAfile /etc/pki/CA/cacert.pem -issuer /etc/pki/CA/cacert.pem -cert dummy.isrlabs.net.crt -url http://ca.isrlabs.net:8888 -resp_text

	OCSP Response Status: successful (0×0)
	Response Type: Basic OCSP Response
	…
	Certificate ID:
	Hash Algorithm: sha1
	Issuer Name Hash: 922CD93C975EDC121DB25B1A55BA9B544E06F9B3
	Issuer Key Hash: 322A8DBF79BE1A934543DC4F24FC69220A2803BA
	Serial Number: 06
	Cert Status: revoked
	Revocation Time: Feb 27 01:07:36 2012 GMT
	This Update: Feb 27 01:12:08 2012 GMT
	…
	Response verify OK
	dummy.isrlabs.net.crt: revoked
	This Update: Feb 27 01:12:08 2012 GMT
	Revocation Time: Feb 27 01:07:36 2012 GMT

If you were to install this cert on a website, and the CA certificate was installed, any modern browser should refuse to connect to the site as the cert has been revoked.

Source: http://isrlabs.net/wordpress/?p=169