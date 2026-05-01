<?php
session_start();
require_once("db.php");
require_once __DIR__ . "/bootstrap_crypto.php";

$keys = getActiveKeys();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: login-company.php");
    exit();
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    $_SESSION['companyLoginError'] = "Invalid Email or Password!";
    header("Location: login-company.php");
    exit();
}

$emailHash = email_hash($email);

$sql = "SELECT id_company, companyname, password, active, email_enc, key_version FROM company WHERE email_hash = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $emailHash);
$stmt->execute();
$res = $stmt->get_result();

if (!$res || $res->num_rows === 0) {
    $stmt->close();
    $_SESSION['companyLoginError'] = "Invalid Email or Password!";
    header("Location: login-company.php");
    exit();
}

$row = $res->fetch_assoc();
$stmt->close();

if (!password_verify($password, $row['password'])) {
    $_SESSION['companyLoginError'] = "Invalid Email or Password!";
    header("Location: login-company.php");
    exit();
}

if ((string)$row['active'] === '2') {
    $_SESSION['companyLoginError'] = "Your Account Is Still Pending Approval.";
    header("Location: login-company.php");
    exit();
}
if ((string)$row['active'] === '0') {
    $_SESSION['companyLoginError'] = "Your Account Is Not Active.";
    header("Location: login-company.php");
    exit();
}

// Decrypt email (optional)
try {
    $k = KeyManager::getKeysByVersion((int)$row['key_version']);
    $plainEmail = MultiEncrypt::decryptField($row['email_enc'], "email", "company", $k);
} catch (Exception $e) {
    $plainEmail = $email;
}

session_regenerate_id(true);
$_SESSION['companyLogged'] = true;
$_SESSION['id_company'] = (int)$row['id_company'];
$_SESSION['companyname'] = $row['companyname']; // optionally decrypt companyname_enc later
$_SESSION['email'] = $plainEmail;

$conn->close();
header("Location: company/index.php");
exit();
