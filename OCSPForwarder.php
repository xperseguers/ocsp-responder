<?
error_reporting(E_ALL);
require('PKIX/OCSP/OCSPMessage.php');
require('PKIX/OCSP/Store.php');
//require_once('../PKIX/utils.php');

define ('HTTP_OK', 200);
define ('HTTP_BAD_REQUEST', 400);
define ('HTTP_UNSUPPORTED_MEDIA_TYPE',	415);
define ('HTTP_METHOD_NOT_ALLOWED',	405);

class HTTPException extends Exception {};

try {
  $cfg = parse_ini_file('/usr/local/etc/OCSPForwarder.ini');
  $reqData = \PKIX\OCSP\Request::receive(array('GET', 'POST'));
  
  $req = new PKIX\OCSP\Request();
  $req->setData($reqData);
  //  $result = $req->GET("http://localhost/ocsp/OCSPServer.php", "POST");
  $result = $req->send($cfg['upstreamURL'], $cfg['HTTPmethod']);
  foreach ($result['headers'] as $h) {
    header($h);
  }
  echo $result['body'];
  exit;
} catch (\PKIX\OCSP\Exception $e) {
  logException($e);

  switch ($e->getCode()) {
  case \PKIX\OCSP::ERR_MALFORMED_ASN1:
  case \PKIX\OCSP::ERR_INTERNAL_ERROR:
  case \PKIX\OCSP::ERR_TRY_LATER:
  case \PKIX\OCSP::ERR_SIG_REQUIRED:
  case \PKIX\OCSP::ERR_UNAUTHORIZED:
    $r = \PKIX\OCSP\ExceptionResponse::createErrorResponse($e->getCode());
    break;
  case \PKIX\OCSP::ERR_REQLIST_EMPTY:
    $r = \PKIX\OCSP\ExceptionResponse::createErrorResponse(\PKIX\OCSP::ERR_MALFORMED_ASN1);
    break;
  case \PKIX\OCSP::STATUS_SUCCESS:
    error_log ("Caugth $e with status code ".$e->getCode()
	       ."which should not happen! Check the code at "
	       .$e->getFile().":".$e->getLine());
    /* no break here - falling back to Internal Server Error */
  default:
    $r = new \PKIX\OCSP\InternalErrorResponse();
    break;
  }
  $r->respond();

} catch (\PKIX\ASN1\HTTPException $e) {
  logException ($e);

  $c = $e->getCode();
  if ($c < 100 || $c > 599) {
    error_log (get_class($e)." called with non HTTP error code $c! "
	       ."Check the code at ".$e->getFile().":".$e->getLine());
    $c = \PKIX\ASN1\HTTP_INTERNAL_SERVER_ERROR;
  }
  sendHTTPError($c);

} catch (\OCSPServer\Exception $e) {
  logException($e);

  switch ($e->getCode()) {
  case OCSPSERVER_ERR_NOTEXIST:
    $r = new \PKIX\OCSP\InternalErrorResponse ();
    break;
  case OCSPSERVER_ERR_NOT_FOUND:
    $r = new \PKIX\OCSP\UnauthorizedResponse ();
    break;
  default:
    error_log (get_class($e)." caught with unexpected code ".$e->getCode()."! "
	       ."Check the code at ".$e->getFile().":".$e->getLine());
    $r = new \PKIX\OCSP\InternalErrorResponse ();
    break;
  }

  $r->respond();

} catch (Exception $e) {
  error_log ("Oops! Caught by enexpected exception "
	     .get_class($e).":[".$e->getCode()."] "
	     . $e->getMessage()." at ".$e->getFile().":".$e->getLine());
  $r = new \PKIX\OCSP\InternalErrorResponse();
  $r->respond();
}

/* utils */
function sendHTTPError ($status) {
  //  header($e->getMessage(), 1, $e->getCode());
  header($_SERVER['SERVER_PROTOCOL']." $status");
}
function logException ($e) {
  error_log ("Caught ".get_class($e).":[".$e->getCode()."] "
	     . $e->getMessage()." at ".$e->getFile().":".$e->getLine());
}
?>