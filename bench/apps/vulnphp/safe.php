<?php
// 벤치 정답셋: 안전 구현 — 여기서는 취약점이 '0건'이어야 한다(오탐 측정용).
$conn = mysqli_connect("localhost", "root", getenv("DB_PASS"), "app");   // 자격증명 분리

$id = intval($_GET['id']);                                               // 정수화
$stmt = $conn->prepare("SELECT * FROM member WHERE id = ?");             // prepared
$stmt->bind_param("i", $id);
$stmt->execute();

echo htmlspecialchars($_GET['msg'], ENT_QUOTES);                         // 출력 인코딩

$hash = password_hash($_POST['pwd'], PASSWORD_DEFAULT);                  // bcrypt
?>
