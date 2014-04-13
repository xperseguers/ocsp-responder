<?php
namespace PKIX\X509 {
	require_once('PKIX/PKIXMessage.php');

	/**
	 * \\PKIX\\X509 specific Exception
	 *
	 */
	class Exception extends \PKIX\ASN1\MessageException {
	}

	/**
	 * %X509 certificate message.  Functionality is very limited.  Only
	 * supports extraction of fields relevant for creating certID for
	 * OCSPRequest (getIssuerNameHash(), getSubjectNameHash(), getKeyHash()).
	 *
	 * Note: Signature verification methods are not implemented!
	 */
	class Certificate extends \PKIX\ASN1\Message {
		const mimeType = 'application/pkix-cert';

		private $version;
		private $serialNumber;
		private $issuer;
		private $subject;
		private $subjectPublicKey;

		/**
		 * Parse data into internal object's structures.
		 *
		 * @param string $data DER-encoded ASN.1 X.509 certificate
		 *
		 * @throw \PKIX\X509\Exception
		 */
		protected function init($data) {
			try {
				$this->_tlv = $this->_parser->parse($data);
				$tbsCertificate = $this->_tlv->first();

				$x = $tbsCertificate->first(); /* version or serialNumber */

				if ($x->getTag() === 0) { /* version */
					$this->version = $x->first()->get();
					$tbsCertificate->next(); /* serialNumber */
					$x = $tbsCertificate->current();
				}
				$this->serialNumber = $x->get();
				$tbsCertificate->next(); /* signature */
				$tbsCertificate->next(); /* issuer */
				$this->issuer = $tbsCertificate->current();
				$tbsCertificate->next(); /* validity */
				$tbsCertificate->next(); /* subject */
				$this->subject = $tbsCertificate->current();
				$tbsCertificate->next(); /* subjectPublicKeyInfo */
				$subjectPublicKeyInfo = $tbsCertificate->current();

				$subjectPublicKeyInfo->first(); /* algorithm */
				$subjectPublicKeyInfo->next(); /* subjectPublicKey */
				$this->subjectPublicKey = $subjectPublicKeyInfo->current();
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		/**
		 * Return digest of the issuername field using algorithm $alg
		 *
		 * @param string $alg OID of the digest algorithm ('1.3.14.3.2.26'
		 * i. e. SHA1 by default
		 *
		 * @retval string hexadecimal representation of the issuername hash
		 */
		public function getIssuerNameHash($alg = '1.3.14.3.2.26') {
			$ser = \ASN1\ASN1::createSerializer(\ASN1\ASN1::createWriter());
			$data = $ser->serialize($this->issuer);
			return $this->_hashData($data, $alg);
		}

		/**
		 * Return digest of the subjetcname field using algorithm $alg
		 *
		 * @param string $alg OID of the digest algorithm ('1.3.14.3.2.26'
		 * i. e. SHA1 by default
		 *
		 * @retval string hexadecimal representation of the subjectname hash
		 */
		public function getSubjectNameHash($alg = '1.3.14.3.2.26') {
			$ser = \ASN1\ASN1::createSerializer(\ASN1\ASN1::createWriter());
			$data = $ser->serialize($this->subject);
			return $this->_hashData($data, $alg);
		}

		/**
		 * Return digest of the subjetcPublicKey field using algorithm $alg
		 *
		 * @param string $alg OID of the digest algorithm ('1.3.14.3.2.26'
		 * i. e. SHA1 by default
		 *
		 * @retval string hexadecimal representation of the
		 * subjectPublicKey hash
		 */
		public function getKeyHash($alg = '1.2.840.113549.1.1.5') {
			$data = $this->subjectPublicKey->read();
			return $this->_hashData(substr($data, 1), /* skip the "unused bits" octet */
				$alg);
		}

		private function _hashData($data, $hashOID) {
			$hashName = static::$OID2Name[$hashOID];
			if (!isset($hashName)) {
				throw new \PKIX\ASN1\UnimplementedException ("Unsupported digest algorithm $alg");
			}
			return openssl_digest($data, $hashName);
		}

		/**
		 * Return the version field from the message.
		 *
		 *
		 * @retval int the certificate version
		 */
		public function getVersion() {
			return $this->version;
		}

		/**
		 * Return the serial number from the message.
		 *
		 *
		 * @retval string the serial number
		 */
		public function getSerialNumber() {
			return $this->serialNumber;
		}

	}
}
