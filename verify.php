<?php
include 'otphp/src/TOTP.php';
include 'assert/lib/Assert/Assertion.php';
include 'base32/src/Base32.php';

use OTPHP\TOTP;
use Base32\Base32;

try{
	$dblink = new PDO('mysql:host=localhost;port=3306;dbname=db_otpphp','root','bajaksaja');
} catch (PDOException $e) {
	http_response_code(500);
	$statuscode = 3;
	$statusstr = "Database error";
	$statusarray = array('code' => $statuscode,'message'=>$statusstr);
	echo json_encode($statusarray);
	//print "Error " . $e->getCode() . ": " . $e->getMessage() . "<br>";
	die();
}

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

$mytotp = new TOTP();
$mytotp->setParameter('digits',$digitlen);
$mytotp->setParameter('secret',$secret);
$mytotp->setParameter('period',60);
$totp = $_POST['otpstr'];

try{
	$query = $dblink->prepare("select attempt,maxattempt from validotptbl where userkey='".$_POST['key']."' AND validated=0 order by timestamp desc");
	$query->execute();
	$result = $query->fetchAll();
	$attempt = $result[0][0];
	$maxattempt = $result[0][1];
	//echo $attempt."-".$maxattempt;
} catch (PDOException $e) {
	http_response_code(500);
	$statuscode = 3;
	$statusstr = "Database error";
	$statusarray = array('code' => $statuscode,'message'=>$statusstr);
	echo json_encode($statusarray);
	//print "Error " . $e->getCode() . ": " . $e->getMessage() . "<br>";
	die();
}

if ($mytotp->verify($totp, null, 1) && ($attempt < $maxattempt || $maxattempt == 0)){
	$statuscode = 0;
	$statusstr = "Your OTP is valid";
	try{
	$query = $dblink->prepare("insert into validotptbl (otpstr,validated,chtime,timestamp,userkey,attempt,maxattempt) values ('" . $totp ."',1,'" . $datech . "'," . $tstamp . ",'".$_POST['key']."',0,0)");
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
	if($attempt < $maxattempt){
		try{
			$query = $dblink->prepare("update validotptbl set attempt=attempt+1 where userkey='".$_POST['key']."'");
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
	}
}

$statusarray = array('code' => $statuscode,'message'=>$statusstr);
echo json_encode($statusarray);

?>
