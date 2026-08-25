<?php
// 벤치 정답셋: 계획적으로 심은 취약점 7종 (OKRA 커스텀 PHP 룰 대상)
$conn = mysqli_connect("localhost", "root", "P@ssw0rd123!", "app");   // [db-cred] 하드코딩

$uid = $_POST['user_id'];
$q = "SELECT * FROM member WHERE user_id='" . $uid . "'";
$res = mysqli_query($conn, $q);                                       // [sqli]

$host = $_GET['host'];
system("ping -c 1 " . $host);                                        // [command]

include $_GET['page'];                                               // [lfi]

echo $_GET['msg'];                                                   // [xss]

$code = $_REQUEST['c'];
eval($code);                                                        // [eval]

$password_hash = md5($_POST['pwd']);                                 // [weak-hash]
?>
