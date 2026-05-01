<?php
require_once __DIR__ . "/crypto/BigInt.php";
require_once __DIR__ . "/crypto/SHA256.php";
require_once __DIR__ . "/crypto/HMAC.php";
require_once __DIR__ . "/crypto/RSA.php";
require_once __DIR__ . "/crypto/ECC.php";
require_once __DIR__ . "/crypto/ECIES.php";
require_once __DIR__ . "/crypto/MultiEncrypt.php";

// 1) SHA256 test
echo "SHA256(abc) = " . SHA256::hash("abc", false) . "<br>";

// 2) RSA test
$rsa = RSA::generate(1024); // for speed; later use 2048
$pub = $rsa->public();
$priv = $rsa->private();
$msg = random_bytes(32);
$ct = RSA::encryptOAEP($msg, $pub, "test");
$pt = RSA::decryptOAEP($ct, $priv, "test");
echo "RSA OK? " . (hash_equals($msg, $pt) ? "YES" : "NO") . "<br>";

// 3) ECC/ECIES test
$ecc = ECC::keygen();
$pt2 = "hello ecies";
$enc = ECIES::encrypt($pt2, $ecc['pub']);
$dec = ECIES::decrypt($enc, $ecc['priv']);
echo "ECIES OK? " . ($dec === $pt2 ? "YES" : "NO") . "<br>";

// 4) MultiEncrypt test
$keys = [
  'version' => 1,
  'rsa_pub' => $pub,
  'rsa_priv' => $priv,
  'ecc_pub' => $ecc['pub'],
  'ecc_priv' => $ecc['priv'],
];

$blob = MultiEncrypt::encryptField("secret@email.com", "email", "user123", $keys);
$plain = MultiEncrypt::decryptField($blob, "email", "user123", $keys);
echo "MultiEncrypt OK? " . ($plain === "secret@email.com" ? "YES" : "NO") . "<br>";
echo "<pre>$blob</pre>";
