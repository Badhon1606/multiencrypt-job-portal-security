<?php
// crypto/MultiEncrypt.php
declare(strict_types=1);

require_once __DIR__ . "/SHA256.php";
require_once __DIR__ . "/HMAC.php";
require_once __DIR__ . "/RSA.php";
require_once __DIR__ . "/ECIES.php";

final class MultiEncrypt
{
    

    public static function encryptField(string $plaintext, string $fieldName, string $userId, array $keys): string
    {
        $version = (int)$keys['version'];

        // 1) Data key per-field
        $K = random_bytes(32);

        // 2) Encrypt data using stream XOR (SHA256 counter mode)
        $nonce = random_bytes(16);
        $cipher = self::xorStream($plaintext, $K, $nonce);

        // 3) Wrap K with RSA-OAEP
        $wrapped_rsa = RSA::encryptOAEP($K, $keys['rsa_pub'], "fieldkey:v{$version}");

        // 4) Wrap RSA blob with ECIES (ECC)
        $ecies = ECIES::encrypt($wrapped_rsa, $keys['ecc_pub']);
        $wrapped_key = json_encode($ecies, JSON_UNESCAPED_SLASHES);

        // 5) MAC (integrity) with derived mac key from K
        $Kmac = SHA256::hash("mac".$K, true);
        $aad = $userId."|".$fieldName."|v=".$version;
        $mac = HMAC::sha256($Kmac, $aad . $nonce . $cipher, true);

        $blob = [
            'v' => $version,
            'alg' => 'RSA-OAEP+ECIES+HMAC-SHA256',
            'nonce' => base64_encode($nonce),
            'cipher' => base64_encode($cipher),
            'wrapped_key' => base64_encode($wrapped_key), // json bytes
            'mac' => base64_encode($mac),
            'aad' => base64_encode($aad),
        ];

        return json_encode($blob, JSON_UNESCAPED_SLASHES);
    }

    public static function decryptField(string $blobJson, string $fieldName, string $userId, array $keys): string
    {
        $blob = json_decode($blobJson, true);
        if (!is_array($blob)) throw new \RuntimeException("Invalid blob JSON");

        $version = (int)$blob['v'];

        $nonce = base64_decode($blob['nonce'], true);
        $cipher = base64_decode($blob['cipher'], true);
        $wrapped_key_json = base64_decode($blob['wrapped_key'], true);
        $mac = base64_decode($blob['mac'], true);
        $aad = base64_decode($blob['aad'], true);

        // 1) unwrap K_rsa using ECC
        $eciesArr = json_decode($wrapped_key_json, true);
        if (!is_array($eciesArr)) throw new \RuntimeException("Invalid wrapped key");
        $wrapped_rsa = ECIES::decrypt($eciesArr, $keys['ecc_priv']); // bytes

        // 2) unwrap K using RSA
        $K = RSA::decryptOAEP($wrapped_rsa, $keys['rsa_priv'], "fieldkey:v{$version}");

        // 3) verify MAC before decrypt
        $Kmac = SHA256::hash("mac".$K, true);
        $expectedAad = $userId."|".$fieldName."|v=".$version;
        if (!hash_equals($expectedAad, $aad)) throw new \RuntimeException("AAD mismatch");

        $expectedMac = HMAC::sha256($Kmac, $aad . $nonce . $cipher, true);
        if (!hash_equals($expectedMac, $mac)) {
            throw new \RuntimeException("MAC verification failed (data modified)");
        }

        // 4) decrypt data
        return self::xorStream($cipher, $K, $nonce);
    }

    private static function xorStream(string $input, string $K, string $nonce): string
    {
        $out = "";
        $counter = 0;
        $offset = 0;
        while ($offset < strlen($input)) {
            $block = SHA256::hash($K . $nonce . pack("N", $counter), true);
            $take = min(32, strlen($input) - $offset);
            $out .= (substr($input, $offset, $take) ^ substr($block, 0, $take));
            $offset += $take;
            $counter++;
        }
        return $out;
    }
}
