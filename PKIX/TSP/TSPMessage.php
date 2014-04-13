<?php
namespace PKIX\TSP {
	require_once('PKIX/PKIXMessage.php');

	const ERR_SUCCESS = 0;
	const ERR_MALFORMED_ASN1 = 1;
	const ERR_UNSUPPORTED_VERSION = 2;

	/**
	 * \\PKIX\\TSP specific Exception
	 *
	 */
	class Exception extends \PKIX\ASN1\MessageException {
	}

	/**
	 * %TSP request message.  Minimal TSP request (RFC2560, RFC5019)
	 * message implementation.  Does not support nonces.
	 *
	 * Note: Signature validation related methods are not implemented!
	 *
	 * The typical usage might be:
	 *
	 * @include TSPRequest-usage.php
	 */
	class Request extends \PKIX\ASN1\Message {
		const mimeType = 'application/timestamp-query';
		const TSP_Version = 1;

		protected $version;
		protected $hashAlgorithm;
		protected $hashedMessage;

		/**
		 * Parse data into internal object's structures.
		 *
		 * @param string $data DER-encoded ASN.1 TSPRequest
		 *
		 * @throw \PKIX\TSP\Exception
		 */
		protected function init($data) {
			try {
				$this->_tlv = $this->_parser->parse($data);
				$this->version = $this->_tlv->first()->get();

				if ($this->version != static::TSP_Version) {
					throw new Exception ("Unsupported protocol version "
						. $this->version
						. " (expected " . static::TSP_Version . ")",
						ERR_UNSUPPORTED_VERSION);
				}

				$this->_tlv->next();
				$messageImprint = $this->_tlv->current();
				$hashAlg = $messageImprint->first();
				$this->hashAlgorithm = $hashAlg->first()->get();

				$messageImprint->next();
				$this->hashedMessage = $messageImprint->current()->get();
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		/**
		 * Create a new \\PKIX\\TSP\\Request from parameters provided in
		 * $params. The request is minimal but compliant with RFC3161 and
		 * can be used to query a TSP server.
		 *
		 * @param array $params contains configuration parameters for the
		 * message:
		 * - hashAlgorithm - string representation of hash algorithm OID
		 * - hashedMessage - hex representation of the hashed message
		 *
		 * @retval \PKIX\TSP\Request new instance
		 */
		public function createFromParams(array $params) {
			/*
			TimeStampReq ::= SEQUENCE  {
			version                  INTEGER  { v1(1) },
			messageImprint           MessageImprint,
			--a hash algorithm OID and the hash value of the data to be
			--time-stamped
			reqPolicy                TSAPolicyId                OPTIONAL,
			nonce                    INTEGER                    OPTIONAL,
			certReq                  BOOLEAN                    DEFAULT FALSE,
			extensions               [0] IMPLICIT Extensions    OPTIONAL  }

			MessageImprint ::= SEQUENCE  {
			hashAlgorithm                AlgorithmIdentifier,
			hashedMessage                OCTET STRING  }
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

			$hashedMessage = \ASN1\TLV\OctetString::create();
			$hashedMessage->set($params['hashedMessage']);

			$messageImprint
				= new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$messageImprint->add($hashAlg);
			$messageImprint->add($hashedMessage);

			$version = \ASN1\TLV\Integer::create();
			$version->set(static::TSP_Version);

			$tsReq = new \ASN1\TLV((object)array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_CONSTRUCTED,
				'Tag' => TLV_TAG_SEQUENCE));
			$tsReq->add($version);
			$tsReq->add($messageImprint);

			$writer = \ASN1\ASN1::createWriter();
			$ser = \ASN1\ASN1::createSerializer($writer);
			$data = $ser->serialize($tsReq);
			return new static($data);
		}

		/**
		 * Return TimeStampReq.version
		 *
		 * @retval int version
		 */
		public function getVersion() {
			return $this->version;
		}

		/**
		 * Return the hash algorithm used to create the hashedMessage
		 *
		 * @retval string representation of hash algorithm OID
		 */
		public function getHashAlgorithm() {
			return $this->hashAlgorithm;
		}

		/**
		 * Return the hashedMessage from the request
		 *
		 * @retval string hex representation of the hashed message
		 */
		public function getHashedMessage() {
			return $this->hashedMessage;
		}
	}

	/**
	 * %TSP response message (RFC3161).  Provides acces to important
	 * message fields like generated time, serial number, accuracy, TSA
	 *  policy.  Currently does not support signature verification.
	 *
	 * Typical usage:
	 *
	 * @include TSPResponse-usage.php
	 */
	class Response extends \PKIX\ASN1\Message {
		const mimeType = 'application/timestamp-reply';

		const STATUS_GRANTED = 0;
		const STATUS_GRANTED_WITH_MODS = 1;
		const STATUS_REJECTION = 2;
		const STATUS_WAITING = 3;
		const STATUS_REVOCATION_WARNING = 4;
		const STATUS_REVOCATION_NOTIFICATION = 5;

		const FAILURE_BAD_ALG = 0;
		const FAILURE_BAD_REQUEST = 2;
		const FAILURE_BAD_DATA_FORMAT = 5;
		const FAILURE_TIME_NOT_AVAILABLE = 14;
		const FAILURE_UNACCEPTED_POLICY = 15;
		const FAILURE_UNACCEPTED_EXTENSION = 16;
		const FAILURE_ADDINFO_NOT_AVAILABLE = 17;
		const FAILURE_SYSTEM_FAILURE = 25;

		const OID_SignedData = '1.2.840.113549.1.7.2';
		const OID_TSTInfo = '1.2.840.113549.1.9.16.1.4';

		protected $status;
		protected $TSTInfo;
		protected $failInfo;

		/**
		 * Parse $data into internal object's structures.  Only some of
		 * the message fields (version, policy, serial number, generated
		 * time, accuracy, ordering) are extracted.
		 *
		 * @param $data DER-encoded ASN.1 TSPResponse
		 *
		 * @throw PKIX::TSP::Exception
		 */
		protected function init($data) {
			try {
				$this->_tlv = $this->_parser->parse($data);

				$statusInfo = $this->_tlv->first();
				$this->status = $status = $statusInfo->first()->__toString();

				$this->_tlv->next();
				if ($this->_tlv->valid()) {
					$timeStampToken = $this->_tlv->current();
				}

				if ($status == 0 || $status == 1) { /* timeStampToken MUST be present */
					if (!$timeStampToken) {
						throw new Exception("Syntax error: timeStampToken not present",
							ERR_MALFORMED_ASN1);
					}

					$contentType = $timeStampToken->first();
					if ($contentType != static::OID_SignedData) {
						throw new Exception("Syntax error: wrong timeStampToken.contentType: $contentType (expected " . static::OID_SignedData . ")",
							ERR_MALFORMED_ASN1);
					}

					$content = $timeStampToken->find(array('Class' => TLV_CLASS_CONTEXT,
						'Type' => TLV_TYPE_CONSTRUCTED,
						'Tag' => 0));
					$signedData = $content->first(); /* CMSVersion */
					$signedData->next(); /* digestAlgoritms */
					$signedData->next(); /* encapContentInfo */
					$encapContentInfo = $signedData->current();

					$eContentType = $encapContentInfo->first();
					if ($eContentType != static::OID_TSTInfo) {
						throw new Exception ("Syntax error: wrong eContentType: $eContentType (expected " . static::OID_TSTInfo . ")",
							ERR_MALFORMED_ASN1);
					}
					$eContent
						= $encapContentInfo->find(array('Class' => TLV_CLASS_CONTEXT,
						'Type' => TLV_TYPE_CONSTRUCTED,
						'Tag' => 0));
					$eContentOS
						= $eContent->find(array('Class' => TLV_CLASS_UNIVERSAL,
						'Type' => TLV_TYPE_PRIMITIVE,
						'Tag' => TLV_TAG_OCTETSTRING));
					/* DBG */
					//	  error_log("eContentOS: sha1:".sha1($eContentOS->read()));

					$this->TSTInfo = new TSTInfo($eContentOS->read());

				} else { /* failInfo MUST be present */
					$this->failInfo
						= $statusInfo->find(array('Class' => TLV_CLASS_UNIVERSAL,
						'Type' => TLV_TYPE_PRIMITIVE,
						'Tag' => TLV_TAG_BITSTRING));
					if (!$this->failInfo) {
						throw new Exception("Syntax error: failInfo not present",
							ERR_MALFORMED_ASN1);
					}
					if (isset($timeStampToken)) {
						throw new Exception("Syntax error: timeStampToken cannot be present with status=$status",
							ERR_MALFORMED_ASN1);
					}
				}
				/* skipped: certificates, crls, signerInfos */
			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		/**
		 * Return the status field from the message. Possible values are
		 * (RFC3161):
		 * - STATUS_GRANTED (0)
		 * - STATUS_GRANTED_WITH_MODS (1)
		 * - STATUS_REJECTION (2)
		 * - STATUS_WAITING (3)
		 * - STATUS_REVOCATION_WARNING (4)
		 * - STATUS_REVOCATION_NOTIFICATION (5)
		 *
		 * @retval int status
		 */
		public function getStatus() {
			return $this->status;
		}

		/**
		 * Return failure information from the message. Possible values
		 * are (RFC3161):
		 * - FAILURE_BAD_ALG (0)
		 * - FAILURE_BAD_REQUEST (2)
		 * - FAILURE_BAD_DATA_FORMAT (5)
		 * - FAILURE_TIME_NOT_AVAILABLE (14)
		 * - FAILURE_UNACCEPTED_POLICY (15)
		 * - FAILURE_UNACCEPTED_EXTENSION (16)
		 * - FAILURE_ADDINFO_NOT_AVAILABLE (17)
		 * - FAILURE_SYSTEM_FAILURE (25)
		 *
		 * @retval array containig failure code(s)
		 */
		public function getFailInfo() {
			return $this->failInfo;
			$type = $this->failInfo->type();
			//      return $this->failInfo->get();
			return $type::bs2array($this->failInfo->get());
		}

		/**
		 * Return TSTInfo.version
		 *
		 * @retval int version
		 */
		public function getVersion() {
			return $this->TSTInfo->getVersion();
		}

		/**
		 * Return TSTInfo.TSAPolicyId
		 *
		 * @retval string policy OID
		 */
		public function getTSAPolicyId() {
			return $this->TSTInfo->getTSAPolicyId();
		}

		/**
		 * Return TSTInfo.serialNumber
		 *
		 * @retval int serial number
		 */
		public function getSerialNumber() {
			return $this->TSTInfo->getSerialNumber();
		}

		/**
		 * Return the generated time (TSTInfo.genTime) from the
		 * message.
		 *
		 * @retval DateTime genTime
		 */
		public function getGenTime() {
			return self::DateTimefromString($this->TSTInfo->getGenTime());
		}

		/**
		 * Return the time accuracy (TSTInfo.accuracy) information from
		 * the message.
		 *
		 * @retval array with the following fields:
		 * - seconds
		 * - milis
		 * - micros
		 * See RFC3161 for the meaning.
		 */
		public function getAccuracy() {
			return $this->TSTInfo->getAccuracy();
		}

		/**
		 * Return the ordering information (TSTInfo.ordering) from the
		 * message.
		 *
		 * @retval bool True if ordering is supported false otherwise
		 */
		public function getOrdering() {
			return $this->TSTInfo->getOrdering();
		}

		/**
		 * Return the nonce (TSTInfo.nonce) from the message.
		 *
		 * @retval string the nonce
		 *
		 * @throw \PKIX\TSP\Exception
		 */
		public function getNonce() {
			return $this->TSTInfo->getNonce();
		}
	}

	/**
	 * %TSTInfo message.
	 *
	 * Note: Signature validation related methods are not implemented!
	 *
	 */
	class TSTInfo extends \PKIX\ASN1\Message {
		const TSP_Version = 1;

		protected $genTime;
		protected $_content; /* keys: version, TSAPolicyId,
				   serialNumber, genTime, accuracy,
				   ordering, nonce */

		/**
		 * Parse $data into internal object's structures.
		 *
		 * @param string $data DER-encoded ASN.1 TSTInfo
		 */
		protected function init($data) {
			try {
				$c = array();
				$this->_tlv = $this->_parser->parse($data);

				//	$x = $this->_tlv->first();
				$c['version'] = $this->_tlv->first()->get();
				if ($c['version'] != static::TSP_Version) {
					throw new Exception("Unsupported TSTInfo version ($c[version])",
						ERR_UNUPPORTED_VERSION);
				}
				$this->_tlv->next(); /* TSAPolicyId */
				$c['TSAPolicyId'] = $this->_tlv->current()->get();

				$this->_tlv->next(); /* MessageImprint */
				$this->_tlv->next(); /* serialNumber */
				$c['serialNumber'] = $this->_tlv->current()->get();

				$this->_tlv->next(); /* genTime */
				$c['genTime'] = $this->_tlv->current()->get();

				for ($this->_tlv->next(); $this->_tlv->valid(); $this->_tlv->next()) {
					$ctlv = $this->_tlv->current();

					switch ($ctlv->getClass()) {

						case TLV_CLASS_UNIVERSAL:
							switch ($ctlv->getTag()) {

								case TLV_TAG_SEQUENCE: /* accuracy */
									$c['accuracy'] = $this->readAccuracy($ctlv);
									break;

								case TLV_TAG_BOOLEAN: /* ordering */
									$c['ordering'] = $ctlv->get();
									break;

								case TLV_TAG_INTEGER: /* nonce */
									$c['nonce'] = $ctlv->read();
									break;

								default:
									throw new Exception("Syntax error: Unexpected TLV (Class: "
										. $ctlv->getClass() .
										", Type: " . $ctlv->getType()
										. ", Tag: " . $ctlv->getTag(),
										ERR_MALFORMED_ASN1);
							}
							break;

						case TLV_CLASS_CONTEXT:
							switch ($ctlv->getTag()) {
								case 0: /* tsa (GeneralName) */
									break;
								case 1: /* extensions (Extensions) */
									break;
								default:
									throw new Exception("Syntax error: Unexpected TLV (Class: "
										. $ctlv->getClass()
										. ", Type: " . $ctlv->getType()
										. ", Tag: " . $ctlv->getTag(),
										ERR_MALFORMED_ASN1);
							}
							break;
						default:
							throw new Exception("Syntax error: Unexpected TLV (Class: "
								. $ctlv->getClass()
								. ", Type: " . $ctlv->getType()
								. ", Tag: " . $ctlv->getTag(),
								ERR_MALFORMED_ASN1);
					}
				}

				$this->_content = $c;

			} catch (\ASN1\TLVMisuseException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			} catch (\ASN1\SeekPastEndOfStreamException $e) {
				throw new Exception ("Malformed request", ERR_MALFORMED_ASN1);
			}
		}

		/**
		 * Read the accuracy information from the message.
		 *
		 * @param \ASN1\TLV $acc the accuracy TLV
		 *
		 * @retval array containing the accuracy information (see
		 * getAccuracy())
		 */
		private function readAccuracy(\ASN1\TLV $acc) {
			$accuracy = array();
			$x = $acc->find(array('Class' => TLV_CLASS_UNIVERSAL,
				'Type' => TLV_TYPE_PRIMITIVE,
				'Tag' => TLV_TAG_INTEGER));
			$accuracy['seconds'] = $x ? $x->getAs(TLV_TAG_INTEGER) : 0;

			$x = $acc->find(array('Class' => TLV_CLASS_CONTEXT,
				'Type' => TLV_TYPE_PRIMITIVE,
				'Tag' => 0));
			$accuracy['milis'] = $x ? $x->getAs(TLV_TAG_INTEGER) : 0;

			$x = $acc->find(array('Class' => TLV_CLASS_CONTEXT,
				'Type' => TLV_TYPE_PRIMITIVE,
				'Tag' => 1));
			$accuracy['micros'] = $x ? $x->getAs(TLV_TAG_INTEGER) : 0;
			return $accuracy;
		}

		/**
		 * Return TSTInfo.version
		 *
		 * @retval int version
		 */
		public function getVersion() {
			return $this->_content['version'];
		}

		/**
		 * Return TSTInfo.TSAPolicyId
		 *
		 * @retval string policy OID
		 */
		public function getTSAPolicyId() {
			return $this->_content['TSAPolicyId'];
		}

		/**
		 * Return TSTInfo.serialNumber
		 *
		 * @retval int serial number
		 */
		public function getSerialNumber() {
			return $this->_content['serialNumber'];
		}

		/**
		 * Return the generated time (TSTInfo.genTime) from the
		 * message.
		 *
		 * @retval DateTime genTime
		 */
		public function getGenTime() {
			return $this->_content['genTime'];
		}

		/**
		 * Return the time accuracy (TSTInfo.accuracy) information from
		 * the message.
		 *
		 * @retval array with the followin fields:
		 * - seconds
		 * - milis
		 * - micros
		 * See RFC3161 for the meaning.
		 */
		public function getAccuracy() {
			return $this->_content['accuracy'];
		}

		/**
		 * Return the ordering information (TSTInfo.ordering) from the
		 * message.
		 *
		 * @retval bool True if ordering is supported false otherwise
		 *
		 */
		public function getOrdering() {
			return $this->_content['ordering'];
		}

		/**
		 * Return the nonce (TSTInfo.nonce) from the message.
		 *
		 * @retval string the nonce
		 *
		 * @throw \PKIX\TSP\Exception
		 */
		public function getNonce() {
			return $this->_content['nonce'];
		}
	}
}
