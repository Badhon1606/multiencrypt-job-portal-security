<?php
declare(strict_types=1);

require_once __DIR__ . "/crypto/BigInt.php";
require_once __DIR__ . "/crypto/SHA256.php";
require_once __DIR__ . "/crypto/HMAC.php";
require_once __DIR__ . "/crypto/RSA.php";
require_once __DIR__ . "/crypto/ECC.php";
require_once __DIR__ . "/crypto/ECIES.php";
require_once __DIR__ . "/crypto/MultiEncrypt.php";

require_once __DIR__ . "/keymgmt/KeyManager.php";

function getActiveKeys(): array {
    return KeyManager::getActiveKeys();
}

/** Deterministic email hash for lookup */
function email_hash(string $email): string {
    return hash('sha256', strtolower(trim($email)));
}
