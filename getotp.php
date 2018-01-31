<?php
include 'otphp/src/TOTP.php';
include 'assert/lib/Assert/Assertion.php';
include 'base32/src/Base32.php';

use OTPHP\TOTP;
use Base32\Base32;

date_default_timezone_set('Asia/Jakarta');
$datenow = date('l jS \of F Y h A');
$datech = date('l jS \of F Y h:m:s A');
$tstamp = date_timestamp_get(date_create());
//$secret = Base32::encode($datenow);
$secret = Base32::encode($_GET['key']);
if(isset($_GET['maxattempt']) && $_GET['maxattempt'] > 0){
	$max = $_GET['maxattempt'];
}else{
	$max = 0;
}
if(isset($_GET['expire']) && $_GET['expire']>60){
	$expire = $_GET['expire'];
}else{
	$expire = 60;
}
if($secret == ""){
	http_response_code(500);
	$statuscode = 2;
	$statusstr = "Please provide a key";
	$statusarray = array('code' => $statuscode,'message'=>$statusstr);
	echo json_encode($statusarray);
	die();
}
$digitlen = $_GET['digit'];
if($digitlen == ""|$digitlen < 2|$digitlen > 10)
	$digitlen = 4;

$mytotp = new TOTP();
$mytotp->setParameter('digits',$digitlen);
$mytotp->setParameter('secret',$secret);
$mytotp->setParameter('period',$expire);
$totp = $mytotp->now();
//insert into db
try{
$dblink = new PDO('mysql:host=localhost;port=3306;dbname=db_otpphp','root',''); // untuk keperluan testing
//$dblink = new PDO('mysql:host=otpdbsvc;port=3306;dbname=db_otpphp','root','docker');
$query = $dblink->prepare("insert into validotptbl (otpstr,validated,chtime,timestamp,userkey,attempt,maxattempt,expire) values ('" . $totp ."',0,'" . $datech . "'," . $tstamp . ",'".$_GET['key']."',0,".$max.",".$expire.")");
$query->execute();
} catch (PDOException $e) {
	http_response_code(500);
	$statuscode = 3;
	$statusstr = "Database error";
	$statusarray = array('code' => $statuscode,'message'=>$statusstr);
	echo json_encode($statusarray);
	//print "Error " . $e->getCode() . ": " . $e->getMessage() . "<br>";
	die();
}

$statuscode = 0;
$totparray = array('code' => $statuscode,'message'=>$totp);
echo json_encode($totparray);
?>
