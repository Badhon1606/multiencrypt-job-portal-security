<?php
require_once "db.php";
require_once "bootstrap_crypto.php";

$keys = getActiveKeys();

$res = $conn->query("SELECT id_user, email FROM users WHERE email_hash IS NULL");

while ($row = $res->fetch_assoc()) {
    $email = $row['email'];
    if (!$email) continue;

    $hash = email_hash($email);
    $enc  = MultiEncrypt::encryptField($email, "email", "candidate", $keys);

    $stmt = $conn->prepare("
        UPDATE users
        SET email_hash = ?, email_enc = ?, key_version = ?
        WHERE id_user = ?
    ");
    $v = $keys['version'];
    $stmt->bind_param("ssii", $hash, $enc, $v, $row['id_user']);
    $stmt->execute();
    $stmt->close();
}

echo "Migration complete";
