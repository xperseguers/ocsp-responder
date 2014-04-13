<?php
/*
 * PHP OCSPRequest - OCSP Request access library for PHP
 *
 */

namespace PKIX\OCSP {

	require_once('PKIX/PKIXMessage.php');

	const ERR_SUCCESS = 0;
	const ERR_MALFORMED_ASN1 = 1;
	const ERR_INTERNAL_ERROR = 2;
	const ERR_TRY_LATER = 3;
	const ERR_SIG_REQUIRED = 5;
	const ERR_UNAUTHORIZED = 6;
	const ERR_UNSUPPORTED_VERSION = 12;
	const ERR_REQLIST_EMPTY = 13;
	const ERR_REQLIST_MULTI = 14;
	const ERR_UNSUPPORTED_EXT = 15;
	const ERR_UNSUPPORTED_ALG = 16;

	const CERT_STATUS_GOOD = 0;
	const CERT_STATUS_REVOKED = 1;
	const CERT_STATUS_UNKNOWN = 2;


	class Exception extends \PKIX\ASN1\MessageException {
	}

	/**
	 * %OCSP request message
	 *
	 */
	class Request extends \PKIX\ASN1\Message {
		const mimeType = 'application/ocsp-request';

		protected $CertID;
		/* protected $_cidkeys = array('hashAlgorithm', */
		/* 				'issuerNameHash', */
		/* 				'issuerKeyHash', */
		/* 				'serialNumber'); */

		/**
		 * Parse $data into internal object's structures.  Only
		 * information needed to identify the requested response is
		 * extracted.  This is actually just the CertID (RFC2560)
		 * structure.  Only the first request of the requestList is
		 * extracted.
		 *
		 * @param string $data DER-encoded ASN.1 OCSPRequest
		 * @throw \PKIX\OCSP\Exception
		 */

		protected function init($data) {
			try {
				$this->_tlv = $this->_parser->parse($data);

				$tbsRequest = $this->_tlv->first();
				$version = $tbsRequest->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 0));
				if ($version != null) { /* non-default value */
					if ($version->get() != 0) {
						throw new Exception ("Unsupported OCSPRequest message version",
							ERR_UNSUPPORTED_VERSION);
					}
				}

				/* skipped: requestorName */

				/* requestExtensions: nonce, AcceptableResponseTypes, ServiceLocator
				 * Find out if any critical extension is requested.
				 * RFC2560 says there should be none but in case there are some
				 * we should give up as we don't support any extension ;)
				*/
				$requestExtensions
					= $tbsRequest->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 2));
				if ($requestExtensions) {
					$extensions = $requestExtensions->first();
					foreach ($extensions as $i => $extension) {
						$extoid = $extension->first()->get();
						$critical = $extension->find(array('Class' => TLV_CLASS_UNIVERSAL,
							'Tag' => TLV_TAG_BOOLEAN));
						if ($critical) {
							throw new Exception ("Unsupported critical extension $extoid",
								ERR_UNSUPPORTED_EXT);
						}
					}
				}

				$requestList = $tbsRequest->find(array('Class' => TLV_CLASS_UNIVERSAL,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => TLV_TAG_SEQUENCE));

				$reqCnt = $requestList->count();
				if ($reqCnt == 0) {
					throw new Exception ("No certificate status requested",
						ERR_REQLIST_EMPTY);
				}
				if ($reqCnt > 1) {
					throw new Exception ("Multiple certificate status requested",
						ERR_REQLIST_MULTI);
				}

				$request = $requestList->first();

				$singleRequestExtensions
					= $request->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 0));
				if ($singleRequestExtensions != null) {
					/* check for critical extensions, break if found some*/
					foreach ($signleRequestExtensions as $extension) {
						$extoid = $extension->first()->get();
						$critical = $extension->find(array('Class' => TLV_CLASS_UNIVERSAL,
							'Tag' => TLV_TAG_BOOLEAN));
						if ($critical) {
							throw new Exception ("Unsupported critical extension $extoid",
								ERR_UNSUPPORTED_EXT);
						}
					}
				}

				$this->CertID = self::parseCertID($request->first());

			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		/**
		 * Parse a CertID TLV
		 *
		 * @param \ASN1\TLV $CID
		 * @retval array The returned array contains four fields
		 * identifying a certificate:
		 * - hashAlgorithm - string representaion of the hash algorithm OID
		 * - issuerNameHash - hex representation of issuerNameHash
		 * - issuerKeyHash - hex representation of issuerkeyHash
		 * - serialNumber - the certificate serial number
		 */

		static function parseCertID(\ASN1\TLV $CID) {
			$CertID = array();
			$keys = array('hashAlgorithm',
				'issuerNameHash',
				'issuerKeyHash',
				'serialNumber');
			foreach ($CID as $i => $tlv) {
				if ($i == 0) { /* hashAlgorithm */
					$CertID[$keys[$i]] = $tlv->first()->__toString();
				} elseif ($i == 3) { /* serialNumber */
					$CertID[$keys[$i]] = self::bcdechex($tlv->__toString());
				} else { /* issuerNameHash, issuerKeyHash */
					$CertID[$keys[$i]] = $tlv->__toString();
				}
			}
			return $CertID;
		}

		/**
		 * Return the reqCert of the first request in the message
		 *
		 * @retval array CertID (see parseCertID())
		 */

		public function getCertID() {
			return $this->CertID;
		}

		/**
		 * Create a new \\PKIX\\OCSP\\Request from parameters provided in $params.
		 * The request is minimal but compliant with RFC5019 and can be
		 * used to query an OCSP server.
		 *
		 * @param array $params The array represents the requested
		 * certificate in the from of the CertID. See parseCertID() for
		 * description.
		 */

		public function createFromParams(array $params) {
			/*
			OCSPRequest     ::=     SEQUENCE {
			tbsRequest                  TBSRequest,
			optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

			TBSRequest      ::=     SEQUENCE {
			version             [0] EXPLICIT Version DEFAULT v1,
			requestorName       [1] EXPLICIT GeneralName OPTIONAL,
			requestList             SEQUENCE OF Request,
			requestExtensions   [2] EXPLICIT Extensions OPTIONAL }

			Signature       ::=     SEQUENCE {
			signatureAlgorithm   AlgorithmIdentifier,
			signature            BIT STRING,
			certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

			Version  ::=  INTEGER  {  v1(0) }

			Request ::=     SEQUENCE {
			reqCert                    CertID,
			singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }
			  */

			$hashAlg = new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));

			$algorithm = \ASN1\TLV\OID::create();
			$algorithm->set($params['hashAlgorithm']);

			$parameters = \ASN1\TLV\Null::create();
			$parameters->set(null);

			$hashAlg->add($algorithm);
			$hashAlg->add($parameters);

			$issuerNameHash = \ASN1\TLV\OctetString::create();
			$issuerNameHash->set($params['issuerNameHash']);

			$issuerKeyHash = \ASN1\TLV\OctetString::create();
			$issuerKeyHash->set($params['issuerKeyHash']);

			$serialNumber = \ASN1\TLV\Integer::create();
			$serialNumber->set($params['serialNumber']);

			$certID = new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$certID->add($hashAlg);
			$certID->add($issuerNameHash);
			$certID->add($issuerKeyHash);
			$certID->add($serialNumber);

			$request = new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$request->add($certID);

			$requestList
				= new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$requestList->add($request);

			$tbsRequest = new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$tbsRequest->add($requestList);

			$ocspRequest
				= new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$ocspRequest->add($tbsRequest);

			/* FIXME?
			 we should should consider replacing the following code
			 with argumentless constructor call
			 and setting of the parmeters without the serialize-parse cycle
			   */
			$writer = \ASN1\ASN1::createWriter();
			$ser = \ASN1\ASN1::createSerializer($writer);
			$data = $ser->serialize($ocspRequest);
			return new self($data);
		}
	}

	/**
	 * %OCSP response message.
	 *
	 */
	class Response extends \PKIX\ASN1\Message {
		const mimeType = 'application/ocsp-response';

		protected $knownResponses
			= array('1.3.6.1.5.5.7.48.1.1' => '\PKIX\OCSP\BasicResponse');
		protected $response;
		protected $maxage;

		/**
		 * Parse $data into internal object's structures.  Only
		 * information from the first SingleResponse is extracted.  Only
		 * information needed generate HTTP response headers is extracted
		 * (producedAT, thisUpdate, nextUpdate).
		 *
		 * @param string $data DER-encoded ASN.1 OCSPResponse
		 */

		protected function init($data) {
			try {
				$this->_tlv = $this->_parser->parse($data);

				$responseBytes
					= $this->_tlv->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 0));
				$responseType = $responseBytes->first()->first()->__toString();

				if (isset($this->knownResponses[$responseType])) {
					$response
						= $responseBytes->first()->find(array('Class' => TLV_CLASS_UNIVERSAL,
						'Type' => TLV_TYPE_PRIMITIVE,
						'Tag' => TLV_TAG_OCTETSTRING));
					$respClass = $this->knownResponses[$responseType];
					$this->response = new $respClass($response->read());
				}
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		public function getProducedAt() {
			return $this->response->getProducedAt();
		}

		public function getThisUpdate() {
			return $this->response->getThisUpdate();
		}

		public function getNextUpdate() {
			return $this->response->getNextUpdate();
		}

		/**
		 * Return time-related information from the message (actually
		 * calling BasicResponse::getDates())
		 *
		 * @retval array containing
		 * - producedAt - DateTime
		 * - thisUpdate - DateTime
		 * - nexUpdate - DateTime
		 */

		public function getDates() {
			return $this->response->getDates();
		}

		/**
		 * Set maximum time for the message to be cached (used by
		 * respondHeaders()).  When sendind the message as HTTP request,
		 * the 'Cache-Control' header's 'max-age' parameter will not be
		 * larger than $maxage.
		 *
		 * @param int $maxage The maximum caching time in seconds
		 */
		public function setMaxAge($maxage) {
			$this->maxage = $maxage;
		}

		/**
		 * Return the CertID from the first SingleResponse in the
		 * message. Actually calls the BasicResponse::getCertID().
		 *
		 * @retval array CertID (see \\PKIX\\OCSP\\Request::parseCertID()
		 * for format description)
		 */
		public function getCertID() {
			return $this->response->getCertID();
		}

		/**
		 * Return the certStatus from the first SignleResponse in the
		 * message. Actually calls the BasicResponse::getCertID().
		 *
		 * @return array CertStatus. The first element is the certificate
		 * status, which is one of:
		 * - \\PKIX\\OCSP\\CERT_STATUS_GOOD (0)
		 * - \\PKIX\\OCSP\\CERT_STATUS_REVOKED (1)
		 * - \\PKIX\\OCSP\\CERT_STATUS_UNKNOWN (2)
		 *
		 * In case of \\PKIX\\OCSP\\CERT_STATUS_REVOKED, the second
		 * element of CertStatus contains the revocationTime as
		 * DateTime. Othewise, the second element of CertStatus is null.
		 */

		public function getCertStatus() {
			return $this->response->getCertStatus();
		}

		public function getSignerCerts() {
			return $this->response->getSignerCerts();
		}

		public function verifySignature() {
			return $this->response->verifySignature();
		}

		public function getSignedData() {
			return $this->response->getSignedData();
		}

		public function getSignatureAlgorithm() {
			return $this->response->getSignatureAlgorithm();
		}

		public function getSignatureRaw() {
			return $this->response->getSignatureRaw();
		}

		/* HTTP interface */
		/* doc inherited     */
		public function respondHeaders() {
			$h = array(
				'Content-Type' => static::mimeType,
				'Content-Length' => strlen($this->getData()),
				'ETag' => '"' . sha1($this->getData()) . '"',
				'Last-Modified' => $this->getProducedAt()->format($this->dtfmt));
			if ($this->getNextUpdate()) {
				$h['Expires'] = $this->getNextUpdate()->format($this->dtfmt);
			}
			$h['Cache-Control'] = $this->getCacheControl();

			return $h;
		}

		/**
		 * Generate and return the 'Cache-Control' HTTP header according
		 * to RFC5019.
		 *
		 * @retval string Value of the the Cache-Control header
		 */
		private function getCacheControl() {
			$now = time();
			$nextUp = $this->getNextUpdate()->format('U');
			$diff = $nextUp - $now;

			if ($diff < 0) {
				//      if ($diff) {
				$diff = 0;
				$CertID = $this->getCertID();
				error_log("stale response for serial $CertID[serialNumber] (issuerNameHash: $CertID[issuerNameHash], issuerKeyHash: $CertID[issuerKeyHash])");
			}
			if (isset($this->maxage)) {
				if ($this->maxage > $diff) {
					$ma = $diff;
				} else {
					$ma = $this->maxage;
				}
			} else {
				$ma = $diff;
			}
			return "max-age=" . $ma . ",public,no-transform,must-revalidate";
		}
	}

	/**
	 * BasicResponse message (see RFC2560)
	 *
	 */
	class BasicResponse extends \PKIX\ASN1\Message {
		protected $producedAt;    /**< DateTime */
		//    protected $thisUpdate;
		//    protected $nextUpdate;
		protected $responses;
		/**< ASN1::TLV */
		protected $singleResponse;    /**< the first PKIX::ASN1::SingleResponse */

		/**
		 * Parse $data into internal object's structures. Only
		 * information from the first SingleResponse is extracted. Only
		 * information needed generate HTTP response headers is extracted
		 * (producedAT, thisUpdate, nextUpdate).
		 *
		 * @param string $data DER-encoded ASN.1 BasicResponse
		 */
		protected function init($data) {
			try {

				$this->_tlv = $this->_parser->parse($data);

				$tbsResponseData = $this->_tlv->first();
				$x
					= $tbsResponseData->find(array('Class' => TLV_CLASS_UNIVERSAL,
					'Type' => TLV_TYPE_PRIMITIVE,
					'Tag' => TLV_TAG_GENERALIZEDTIME));
				$this->producedAt = $this->DateTimefromString($x);

				$this->responses
					= $tbsResponseData->find(array('Class' => TLV_CLASS_UNIVERSAL,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => TLV_TAG_SEQUENCE));
				/* We care only about the first SingleResponse */
				$this->singleResponse = new SingleResponse($this->responses->first());

			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		public function getProducedAt() {
			return $this->producedAt;
		}

		public function getThisUpdate() {
			return $this->singleResponse->getThisUpdate();
		}

		public function getNextUpdate() {
			return $this->singleResponse->getNextUpdate();
		}

		/**
		 * Return time-related information from the message.
		 *
		 * @retval array containing
		 * - producedAt - DateTime
		 * - thisUpdate - DateTime
		 * - nexUpdate - DateTime
		 */
		public function getDates() {
			return array('producedAt' => $this->producedAt,
				'thisUpdate' => $this->getThisUpdate(),
				'nextUpdate' => $this->getNextUpdate());
		}

		/**
		 * Return the CertID from the first SingleResponse in the
		 * message. Actually calls the SingleResponse::getCertID().
		 *
		 * @retval array CertID (see \\PKIX\\OCSP\\Request::parseCertID()
		 * for format description)
		 *
		 */
		public function getCertID() {
			return $this->singleResponse->getCertID();
		}

		/**
		 * Return the certStatus from the first SignleResponse in the
		 * message. Actually calls the BasicResponse::getCertID().
		 *
		 * @retval array CertStatus. The first element is the certificate
		 * status, which is one of:
		 * - \\PKIX\\OCSP\\CERT_STATUS_GOOD (0)
		 * - \\PKIX\\OCSP\\CERT_STATUS_REVOKED (1)
		 * - \\PKIX\\OCSP\\CERT_STATUS_UNKNOWN (2)
		 *
		 * In case of \\PKIX\\OCSP\\CERT_STATUS_REVOKED, the second
		 * element of CertStatus contains the revocationTime as
		 * DateTime. Othewise, the second element of CertStatus is null.
		 *
		 */
		public function getCertStatus() {
			return $this->singleResponse->getCertStatus();
		}

		/** @name Signature Verification (Local implementation)
		 *
		 * Local implementation of signature verification related methods
		 **@{
		 */

		public function getSignedData() {
			$writer = \ASN1\ASN1::createWriter();
			$ser = \ASN1\ASN1::createSerializer($writer);
			return $ser->serialize($this->_tlv->first());
		}

		public function getSignerCerts() {
			try {
				$signerCerts = array();
				$certs = $this->_tlv->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 0));
				foreach ($certs as $cert) {
					array_push($signerCerts, $cert->read());
				}
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
			return $signerCerts;
		}

		public function getSignatureAlgorithm() {
			$this->_tlv->rewind();
			$this->_tlv->first(); /* tbsResponseData */
			$this->_tlv->next(); /* signatureAlgorithm */
			$sigalg = $this->_tlv->current()->first()->get();
			return $sigalg;
		}

		public function getSignatureRaw() {
			$sig = $this->_tlv->find(array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_PRIMITIVE,
				'Tag' => TLV_TAG_BITSTRING))->read();
			return substr($sig, 1); /* skip the "unused bits" octet */
		}
		/*@} end of Signature Verification (Local implementation) */

	}

	/**
	 * SingleResponse message (see RFC2560)
	 *
	 */
	class SingleResponse extends \PKIX\ASN1\Message {
		protected $CertID;
		protected $certStatus;
		protected $thisUpdate;
		protected $nextUpdate;

		/**
		 * Constructor
		 *
		 * @param \ASN1\TLV $tlv The TLV containing the preparsed
		 * SingleResponse data.  If present, it will be used to initialize
		 * the object.
		 *
		 * @retval \PKIX\OCSP\SingleResponse instance
		 */
		public function __construct($tlv = null) {
			if (isset($tlv)) {
				$this->setTLV($tlv);
				$this->init($tlv);
			}
		}

		/**
		 * Initialize the object from $data
		 *
		 * @param \ASN1\TLV $data TLV containing the preparsed
		 * SingleResponse data
		 */
		protected function init($data) {
			return $this->initFromTLV();
		}

		public function setTLV(\ASN1\TLV $tlv) {
			$this->_tlv = $tlv;
		}

		private function initFromTLV() {
			try {
				/*
				 * We parse only thisUpdate and nextUpdate fields by default.
				 * Other fields are only parsed when requested by get* methods.
				 */
				$x = $this->_tlv->find(array('Class' => TLV_CLASS_UNIVERSAL,
					'Type' => TLV_TYPE_PRIMITIVE,
					'Tag' => TLV_TAG_GENERALIZEDTIME));
				$this->thisUpdate = $this->DateTimefromString($x);

				$nU = $this->_tlv->find(array('Class' => TLV_CLASS_CONTEXT,
					'Type' => TLV_TYPE_CONSTRUCTED,
					'Tag' => 0));
				if ($nU) {
					$x = $nU->first(); /* nextUpdate is explicit */
					$this->nextUpdate = $this->DateTimefromString($x);
				}
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		public function getThisUpdate() {
			return $this->thisUpdate;
		}

		public function getNextUpdate() {
			return $this->nextUpdate;
		}

		/**
		 * Return the CertID from the message.  The CertID will be read
		 * from the TLV if needed.
		 *
		 * @return array CertID (see \\PKIX\\OCSP\\Request::parseCertID()
		 * for format description)
		 *
		 */
		public function getCertID() {
			if (!isset($this->CertID)) {
				$this->CertID = Request::parseCertID($this->_tlv->first());
			}
			return $this->CertID;
		}

		/**
		 * Return the certStatus from the message.  The certStatus will be
		 * read from the TLV if needed.
		 *
		 * @return array CertStatus. The first element is the certificate
		 * status, which is one of:
		 * - \\PKIX\\OCSP\\CERT_STATUS_GOOD (0)
		 * - \\PKIX\\OCSP\\CERT_STATUS_REVOKED (1)
		 * - \\PKIX\\OCSP\\CERT_STATUS_UNKNOWN (2)
		 *
		 * In case of \\PKIX\\OCSP\\CERT_STATUS_REVOKED, the second
		 * element of CertStatus contains the revocationTime as
		 * DateTime. Othewise, the second element of CertStatus is null.
		 */
		public function getCertStatus() {
			if (!isset($this->certStatus)) {
				$this->certStatus = $this->parseCertStatus();
			}
			return $this->certStatus;
		}

		private function parseCertStatus() {
			$this->_tlv->first(); /* skipping certID */
			$this->_tlv->next();
			$cstlv = $this->_tlv->current();
			$certStatus = array($cstlv->getTag());

			switch ($cstlv->getTag()) {
				case CERT_STATUS_GOOD:
				case CERT_STATUS_UNKNOWN:
					array_push($certStatus, null);
					break;
				case CERT_STATUS_REVOKED:
					$x = $cstlv->first();
					$revTime = $this->DateTimefromString($x);
					array_push($certStatus, $revTime);
					break;
			}
			return $certStatus;
		}

		/** @par Signature Verification
		 *
		 * Signature verification related methods are not implemented by
		 * \\PKIX\\ASN1\\SingleResponse
		 */
	}

	/**
	 * Generic %OCSP error response.  As the response messages are not
	 * signed, the signature verification related functions are not
	 * implemented.
	 *
	 */
	class ExceptionResponse extends Response {
		protected $OCSPStatus;
		protected $HTTPStatus = self::HTTP_OK;
		//    protected $body = '';

		/**
		 * The init() function is no-op for error responses.
		 *
		 * @param mixed $data Ignored
		 */
		protected function init($data) {
		}

		/** @name HTTP interface (local overrides) */
		/**@{*/
    public function respondHeaders() {
		return array('Content-Type' => static::mimeType);
	}

    /* public function HTTPStatusHeader () { */
    /*   if (isset($this->HTTPStatus)) { */
    /* 	return $_SERVER['SERVER_PROTOCOL'].' '.$this->HTTPStatus; */
    /*   } */
    /* } */

    /**@} end of HTTP interface */

    /**
	 * Factory method for creating specific %OCSP error responses.
	 *
	 * @param int $errcode %OCSP error code, one of:
	 * - ERR_MALFORMED_ASN1 (1) (called malformedRequest in RFC2560)
	 * - ERR_INTERNAL_ERROR (2)
	 * - ERR_TRY_LATER (3)
	 * - ERR_SIG_REQUIRED (5)
	 * - ERR_UNAUTHORIZED (6)
	 *
	 * @retval \PKICS\OCSP\ExceptionResponse subclass
	 */
    public static function createErrorResponse($errcode) {
		switch ($errcode) {
			case ERR_MALFORMED_ASN1:
				return new MalformedRequestResponse();
			case ERR_INTERNAL_ERROR:
				return new InternalErrorResponse();
			case ERR_TRY_LATER:
				return new TryLaterResponse();
			case ERR_SIG_REQUIRED:
				return new SigRequiredResponse();
			case ERR_UNAUTHORIZED:
				return new UnauthorizedResponse();
		}
	}

    /**
	 * Create ASN.1 %OCSP error response
	 *
	 */
    public function getData() {
		return pack("C*", 0x30, 0x03, 0x0a, 0x01, $this->OCSPStatus);
	}
  }

	/**
	 * %OCSP malformedRequest response
	 *
	 */
	class MalformedRequestResponse extends ExceptionResponse {
		protected $OCSPStatus = ERR_MALFORMED_ASN1;
	}

	/**
	 * %OCSP internalError response
	 *
	 */
	class InternalErrorResponse extends ExceptionResponse {
		protected $OCSPStatus = ERR_INTERNAL_ERROR;
	}

	/**
	 * %OCSP tryLater response
	 *
	 */
	class TryLaterResponse extends ExceptionResponse {
		protected $OCSPStatus = ERR_TRY_LATER;
	}

	/**
	 * %OCSP sigRequired response
	 *
	 */
	class SigRequiredResponse extends ExceptionResponse {
		protected $OCSPStatus = ERR_INTERNAL_ERROR;
	}

	/**
	 * %OCSP unauthorized response
	 *
	 */
	class UnauthorizedResponse extends ExceptionResponse {
		protected $OCSPStatus = ERR_UNAUTHORIZED;
	}
}
