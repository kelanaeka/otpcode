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
$secret = Base32::encode($datenow);
$mytotp = new TOTP();
$mytotp->setParameter('digits',4);
$mytotp->setParameter('secret',$secret);
$totp = $mytotp->now();
//insert into db
try{
$dblink = new PDO('mysql:host=db;port=3306;dbname=db_otpphp','root','docker');
$query = $dblink->prepare("insert into validotptbl (otpstr,validated,chtime,timestamp) values ('" . $totp ."',0,'" . $datech . "'," . $tstamp . ")");
$query->execute();
} catch (PDOException $e) {
	print "Error " . $e->getCode() . ": " . $e->getMessage() . "<br>";
	die();
}
$totparray = array('otpkey'=>$totp);
echo json_encode($totparray);
?>
