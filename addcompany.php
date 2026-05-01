<?php
session_start();
require_once("db.php");
require_once __DIR__ . "/bootstrap_crypto.php";

$keys = getActiveKeys();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: register-company.php");
    exit();
}

function col_exists(mysqli $conn, string $table, string $col): bool {
    $sql = "SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1";
    $st = $conn->prepare($sql);
    $st->bind_param("ss", $table, $col);
    $st->execute();
    $rs = $st->get_result();
    $ok = ($rs && $rs->num_rows > 0);
    $st->close();
    return $ok;
}

// -------------------- Inputs --------------------
$name        = trim($_POST['name'] ?? '');
$companyname = trim($_POST['companyname'] ?? '');
$country     = trim($_POST['country'] ?? '');
$state       = trim($_POST['state'] ?? '');
$city        = trim($_POST['city'] ?? '');
$contactno   = trim($_POST['contactno'] ?? '');
$website     = trim($_POST['website'] ?? '');
$email       = trim($_POST['email'] ?? '');
$passPlain   = $_POST['password'] ?? '';
$aboutme     = trim($_POST['aboutme'] ?? '');

if ($email === '' || $passPlain === '' || $companyname === '') {
    $_SESSION['registerError'] = true;
    $_SESSION['registerErrorMsg'] = "Companyname, Email and Password are required.";
    header("Location: register-company.php");
    exit();
}

// -------------------- Logo upload (required by DB: logo NOT NULL) --------------------
$logoDir = "uploads/logo/";
if (!is_dir($logoDir)) @mkdir($logoDir, 0777, true);

$logoFile = "";
if (isset($_FILES['logo']) && file_exists($_FILES['logo']['tmp_name'])) {
    $base = basename($_FILES['logo']['name']);
    $ext = strtolower(pathinfo($base, PATHINFO_EXTENSION));
    $allowed = ["png","jpg","jpeg","webp"];

    if (!in_array($ext, $allowed, true)) {
        $_SESSION['registerError'] = true;
        $_SESSION['registerErrorMsg'] = "Logo must be png/jpg/jpeg/webp.";
        header("Location: register-company.php");
        exit();
    }

    if ($_FILES['logo']['size'] >= 5242880) { // 5MB
        $_SESSION['registerError'] = true;
        $_SESSION['registerErrorMsg'] = "Logo too large (max 5MB).";
        header("Location: register-company.php");
        exit();
    }

    $logoFile = uniqid("logo_", true) . "." . $ext;
    if (!move_uploaded_file($_FILES['logo']['tmp_name'], $logoDir . $logoFile)) {
        $_SESSION['registerError'] = true;
        $_SESSION['registerErrorMsg'] = "Logo upload failed.";
        header("Location: register-company.php");
        exit();
    }
} else {
    $_SESSION['registerError'] = true;
    $_SESSION['registerErrorMsg'] = "Logo is required.";
    header("Location: register-company.php");
    exit();
}

// -------------------- Crypto: hash + encrypt everything --------------------
$emailHash = email_hash($email);
$emailEnc  = MultiEncrypt::encryptField($email, "email", "company", $keys);

$enc_name        = MultiEncrypt::encryptField($name, "name", "company", $keys);
$enc_companyname = MultiEncrypt::encryptField($companyname, "companyname", "company", $keys);
$enc_country     = MultiEncrypt::encryptField($country, "country", "company", $keys);
$enc_state       = MultiEncrypt::encryptField($state, "state", "company", $keys);
$enc_city        = MultiEncrypt::encryptField($city, "city", "company", $keys);
$enc_contactno   = MultiEncrypt::encryptField($contactno, "contactno", "company", $keys);
$enc_website     = MultiEncrypt::encryptField($website, "website", "company", $keys);
$enc_aboutme     = MultiEncrypt::encryptField($aboutme, "aboutme", "company", $keys);
$enc_logo        = MultiEncrypt::encryptField($logoFile, "logo", "company", $keys);

$keyVersion = (int)$keys['version'];

// Row-level MAC over encrypted blobs
$rowData =
    $emailEnc .
    $enc_name .
    $enc_companyname .
    $enc_country .
    $enc_state .
    $enc_city .
    $enc_contactno .
    $enc_website .
    $enc_aboutme .
    $enc_logo;

$mac = base64_encode(HMAC::sha256("rowmac_v{$keys['version']}", $rowData, true));

// Password hashing (do not encrypt passwords)
$passwordHash = password_hash($passPlain, PASSWORD_BCRYPT);

// -------------------- Duplicate check (prefer email_hash if exists) --------------------
if (col_exists($conn, "company", "email_hash")) {
    $chk = $conn->prepare("SELECT id_company FROM company WHERE email_hash = ?");
    $chk->bind_param("s", $emailHash);
} else {
    $chk = $conn->prepare("SELECT id_company FROM company WHERE email = ?");
    $chk->bind_param("s", $email);
}
$chk->execute();
$r = $chk->get_result();
if ($r && $r->num_rows > 0) {
    $chk->close();
    $_SESSION['registerError'] = true;
    $_SESSION['registerErrorMsg'] = "Email already exists!";
    header("Location: register-company.php");
    exit();
}
$chk->close();

// -------------------- Build INSERT dynamically to avoid column mismatch --------------------
$cols = [];
$vals = [];
$types = "";
$params = [];

$add = function(string $col, string $type, $val) use (&$cols,&$vals,&$types,&$params) {
    $cols[] = $col;
    $vals[] = "?";
    $types .= $type;
    $params[] = $val;
};

// Core columns (from your database.sql)
$add("name", "s", $name);
$add("companyname", "s", $companyname);
$add("country", "s", $country);
$add("state", "s", $state);
$add("city", "s", $city);
$add("contactno", "s", $contactno);
$add("website", "s", $website);
$add("email", "s", $email);
$add("password", "s", $passwordHash);
$add("aboutme", "s", $aboutme);
$add("logo", "s", $logoFile);
// active default in SQL is '2' – we can omit it OR set it explicitly
if (col_exists($conn, "company", "active")) {
    $add("active", "i", 2);
}

// Crypto columns if they exist
if (col_exists($conn, "company", "email_hash"))   $add("email_hash", "s", $emailHash);
if (col_exists($conn, "company", "email_enc"))    $add("email_enc", "s", $emailEnc);
if (col_exists($conn, "company", "key_version"))  $add("key_version", "i", $keyVersion);
if (col_exists($conn, "company", "mac"))          $add("mac", "s", $mac);

// Encrypted field columns if you created them
if (col_exists($conn, "company", "name_enc"))        $add("name_enc", "s", $enc_name);
if (col_exists($conn, "company", "companyname_enc")) $add("companyname_enc", "s", $enc_companyname);
if (col_exists($conn, "company", "country_enc"))     $add("country_enc", "s", $enc_country);
if (col_exists($conn, "company", "state_enc"))       $add("state_enc", "s", $enc_state);
if (col_exists($conn, "company", "city_enc"))        $add("city_enc", "s", $enc_city);
if (col_exists($conn, "company", "contactno_enc"))   $add("contactno_enc", "s", $enc_contactno);
if (col_exists($conn, "company", "website_enc"))     $add("website_enc", "s", $enc_website);
if (col_exists($conn, "company", "aboutme_enc"))     $add("aboutme_enc", "s", $enc_aboutme);
if (col_exists($conn, "company", "logo_enc"))        $add("logo_enc", "s", $enc_logo);

// Prepare final SQL
$sql = "INSERT INTO company (" . implode(",", $cols) . ") VALUES (" . implode(",", $vals) . ")";
$stmt = $conn->prepare($sql);
if (!$stmt) {
    $_SESSION['registerError'] = true;
    $_SESSION['registerErrorMsg'] = "DB prepare error: " . $conn->error;
    header("Location: register-company.php");
    exit();
}

// bind_param dynamically
$stmt->bind_param($types, ...$params);

if ($stmt->execute()) {
    $stmt->close();
    $conn->close();
    $_SESSION['registerCompleted'] = true;
    header("Location: login-company.php");
    exit();
}

$err = $stmt->error;
$stmt->close();
$conn->close();
$_SESSION['registerError'] = true;
$_SESSION['registerErrorMsg'] = "Registration failed: " . $err;
header("Location: register-company.php");
exit();
