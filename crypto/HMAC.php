<?php
// crypto/HMAC.php
declare(strict_types=1);

require_once __DIR__ . "/SHA256.php";

final class HMAC
{
    public static function sha256(string $key, string $msg, bool $rawOutput = true): string
    {
        $blockSize = 64; // bytes for SHA-256

        if (strlen($key) > $blockSize) {
            $key = SHA256::hash($key, true);
        }
        $key = str_pad($key, $blockSize, "\x00", STR_PAD_RIGHT);

        $o_key_pad = $key ^ str_repeat("\x5c", $blockSize);
        $i_key_pad = $key ^ str_repeat("\x36", $blockSize);

        $inner = SHA256::hash($i_key_pad . $msg, true);
        $hmac  = SHA256::hash($o_key_pad . $inner, true);

        return $rawOutput ? $hmac : bin2hex($hmac);
    }
}
