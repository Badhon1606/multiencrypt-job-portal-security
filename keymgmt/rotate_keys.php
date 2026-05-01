<?php
declare(strict_types=1);

require_once __DIR__ . "/KeyManager.php";

try {
    // 2048 recommended for assignment
    $newV = KeyManager::rotate(2048);
    echo "Key rotation complete. Active version is now: v{$newV}<br>";
    echo "Private keys stored in: C:\\xampp\\secure_keys\\<br>";
    echo "Registry stored in: " . __DIR__ . "\\key_registry.json<br>";
} catch (Exception $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
}
