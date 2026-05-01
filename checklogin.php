<?php
session_start();
require_once("db.php");
require_once __DIR__ . "/bootstrap_crypto.php";

$keys = getActiveKeys();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: login-candidates.php");
    exit();
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    $_SESSION['loginError'] = "Invalid Email or Password!";
    header("Location: login-candidates.php");
    exit();
}

$emailHash = email_hash($email);

// Login lookup by email_hash
$sql = "SELECT id_user, password, active, email_enc, key_version FROM users WHERE email_hash = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $emailHash);
$stmt->execute();
$res = $stmt->get_result();

if (!$res || $res->num_rows === 0) {
    $stmt->close();
    $_SESSION['loginError'] = "Invalid Email or Password!";
    header("Location: login-candidates.php");
    exit();
}

$row = $res->fetch_assoc();
$stmt->close();

// Active check
if ((string)$row['active'] === '0') {
    $_SESSION['loginActiveError'] = "Your Account Is Not Active. Check Your Email.";
    header("Location: login-candidates.php");
    exit();
}

// Password verify
if (!password_verify($password, $row['password'])) {
    $_SESSION['loginError'] = "Invalid Email or Password!";
    header("Location: login-candidates.php");
    exit();
}

// Decrypt email on retrieval (correct version)
try {
    $k = KeyManager::getKeysByVersion((int)$row['key_version']);
    $plainEmail = MultiEncrypt::decryptField($row['email_enc'], "email", "candidate", $k);
} catch (Exception $e) {
    $plainEmail = $email; // fallback
}

// Session
session_regenerate_id(true);
$_SESSION['userLogged'] = true;
$_SESSION['id_user'] = (int)$row['id_user'];
$_SESSION['email'] = $plainEmail;

$conn->close();
header("Location: user/index.php");
exit();
