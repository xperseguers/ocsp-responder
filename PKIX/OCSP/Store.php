<?php
namespace OCSPServer {

	const ERR_CONFIG_ERROR = 1;
	const ERR_NOT_FOUND = 2;

	/**
	 * OCSPServer specific exception
	 *
	 */
	class Exception extends \Exception {
	}

	/**
	 * Abstract class for OCSPServer storage manipulation
	 *
	 */
	abstract class Store {
		/**
		 * Constructor.
		 *
		 * @param array $params Implementation specific configuration
		 * parameters
		 */
		public function __construct(array $params) {
			$this->config($params);
		}

		/**
		 * Configure the storage.
		 *
		 * @param array $params Implementation specific configuration
		 * parameters
		 *
		 * @throw \PKIX\OCSPServer\Exception with code ERR_CONFIG_ERROR
		 */
		abstract public function config(array $params);

		/**
		 * Search the storage for a %OCSP response data for a certificate
		 * identified by $cid.
		 *
		 * @param array $cid CertID array (see
		 * \\PKIX\\OCSP\\Request::parseCertID() for format description)
		 *
		 * @retval string DER-encoded ASN.1 %OCSP response
		 *
		 * @throw \PKIX\OCSPServer\Exception with code ERR_NOT_FOUND when
		 * response not found
		 */
		abstract public function getResp(array $cid);
	}

	/**
	 * Filesystem-based implementation of %OCSP responses storage.
	 *
	 */
	class StoreFS extends Store {
		protected $_basedir;

		/**
		 * Configure the storage.
		 *
		 * @param array $params Array containing the configiration
		 * directives:
		 * - basedir - full path do the storage root directory
		 *
		 * @throw \PKIX\OCSPServer\Exception with value ERR_CONFIG_ERROR
		 */
		public function config(array $params) {
			if (isset($params['basedir'])) {
				$this->setBasedir($params['basedir']);
			}
		}

		/**
		 * Set the storage root directory
		 *
		 * @param string $basedir full path to the storage root directory
		 *
		 * @throw \PKIX\OCSPServer\Exception with value ERR_CONFIG_ERROR
		 */
		public function setBasedir($basedir) {
			if (is_dir($basedir)) {
				$this->_basedir = $basedir;
			} else {
				throw new Exception ("Directory $basedir does not exists",
					ERR_CONFIG_ERROR);
			}
		}

		/* doc inherited */
		public function getResp(array $cid) {
			$path = $this->getPath($cid);
			$resp = @file_get_contents($path);
			if (!$resp) {
				throw new Exception ("Response not found", ERR_NOT_FOUND);
			}
			return $resp;
		}

		/**
		 * Get the path to the response from the CertID $cid
		 *
		 * @param array $cid CertID
		 * @return string the constructed path
		 */
		private function getPath(array $cid) {
			return implode("/",
				array($this->_basedir,
					$cid{'hashAlgorithm'},
					$cid{'issuerNameHash'},
					$cid{'issuerKeyHash'},
					$cid{'serialNumber'}));
		}
	}
}
