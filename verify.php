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
$secret = Base32::encode($_POST['key']);
if($secret == ""){
	http_response_code(500);
	$statuscode = 2;
	$statusstr = "Please provide a key";
	$statusarray = array('code' => $statuscode,'message'=>$statusstr);
	echo json_encode($statusarray);
	die();
}
$digitlen = $_POST['digit'];
if($digitlen == ""|$digitlen < 2|$digitlen > 10)
	$digitlen = 4;
if(isset($_POST['maxattempt']) & $_POST['maxattempt']>=0){
	$max = $_POST['maxattempt'];
}else{
	$max = "~";
}

if(isset($_POST['expire']) & $_POST['expire']>60){
	$expire = $_POST['expire'];
}else{
	$expire = 60;
}
$mytotp = new TOTP();
$mytotp->setParameter('digits',$digitlen);
$mytotp->setParameter('secret',$secret);
$mytotp->setParameter('period',$expire);
$totp = $_POST['otpstr'];

if ($mytotp->verify($totp, null, 1) && ($max>0 || $max == "~")){
	$statuscode = 0;
	$statusstr = "Your OTP is valid";
	try{
	$dblink = new PDO('mysql:host=localhost;port=3306;dbname=db_otpphp','root',''); // Development Purpose
	//$dblink = new PDO('mysql:host=otpdbsvc;port=3306;dbname=db_otpphp','root','docker');
	$query = $dblink->prepare("insert into validotptbl (otpstr,validated,chtime,timestamp) values ('" . $totp ."',1,'" . $datech . "'," . $tstamp . ")");
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
} else {
	http_response_code(500);
	$statuscode = 1;
	$statusstr = "Your OTP is invalid";
}
if($statuscode==0){
	if($max!="~"){
		$max = 0;
	}
}else{
	if($max!="~"){
		$max -= 1;
	}
}
$statusarray = array('code' => $statuscode,'message'=>$statusstr, 'maxattempt'=>$max, 'expire'=>$expire);
echo json_encode($statusarray);

?>
