Submitting OCSP Requests Using the GET Method
=============================================

OCSP requests which are smaller than 255KB can be submitted to the Online Certificate Status Manager using a GET method, as described in RFC 2560. To submit OCSP requests over GET:

1. Generate an OCSP request for the certificate that's status is being queried. For example:

		# OCSPClient server.example.com 11180 /var/lib/pki-ca/alias 'caSigningCert cert-pki-ca' 1 /export/output.txt 1
		URI: /ocsp/ee/ocsp
		Data Length: 68
		Data: MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewdDnn8ZgQUbyBZ
		44kgy35o7xW5BMzM8FTvyTwCAQE=

	The Certificate System's OCSPClient tool has the format:
	
		OCSPClient host port /path/to/CA_cert_database 'CA_signing_cert_nickname' serial_number output_file times

	An OCSP request can also be generated using OpenSSL tools, as described at http://openssl.org/docs/apps/ocsp.html, or through a browser such as Internet Explorer 7.0.

2. Paste the URL in the address bar of a web browser to return the status information. The browser must be able to handle OCSP requests.

		https://server.example.com:11443/ocsp/ee/ocsp/MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE=

3. The OCSP Manager responds with the certificate status which the browser can interpret. The possible statuses are GOOD, REVOKED, and UNKNOWN.

Alternatively, run the OCSP from the command line by using a tool such as wget to send the request and checking the OCSP logs for the response. For example:

1. Generate an OCSP request for the certificate that's status is being queried.

		# OCSPClient server.example.com 11443 /var/lib/pki-ca/alias 'caSigningCert cert-pki-ca' 1 /export/output.txt 1
		URI: /ocsp/ee/ocsp
		Data Length: 68
		Data: MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewdDnn8ZgQUbyBZ
		44kgy35o7xW5BMzM8FTvyTwCAQE=

2. Connect to the OCSP Manager using wget to send the OCSP request.

		wget https://server.example.com:11443/ocsp/ee/ocsp/MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4J
		     pmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE= --no-check-certificate
		--16:34:34-- https://server.example.com:11443/ocsp/ee/ocsp/MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABky
		     iCIhU4JpmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE=
		   =>`MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE='
		Resolving server.example.com... 192.168.123.224
		Connecting to server.example.com|192.168.123.224|:11443... connected.
		WARNING: Certificate verification error for server.example.com: self signed certificate 
		      in certificate chain
		HTTP request sent, awaiting response... 200 OK
		Length: 2,362 (2.3K) [application/ocsp-response]

		100%[======================================================================>] 2,362 --.--K/s

		16:34:34 (474.43 MB/s) - `MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewd
		     Dnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE=' saved [2362/2362]

3. The status for the specified certificate is written to the OCSP's debug log and can be GoodInfo, RevokeInfo, or UnknownInfo.

		[16/Jul/2009:16:48:47][http-11443-Processor24]: Serial Number: 1 
		     Status: com.netscape.cmsutil.ocsp.GoodInfo

Source: https://access.redhat.com/site/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/OCSPRequests-GETMethod.html