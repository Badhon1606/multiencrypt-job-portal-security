<?php
// crypto/ECIES.php
declare(strict_types=1);

require_once __DIR__ . "/ECC.php";
require_once __DIR__ . "/SHA256.php";

final class ECIES
{
    // Encrypt arbitrary bytes for recipient public key (ECPoint)
    public static function encrypt(string $plaintext, ECPoint $recipientPub): array
    {
        // ephemeral keypair
        $ephem = ECC::keygen();
        /** @var \GMP $ke */
        $ke = $ephem['priv'];
        /** @var ECPoint $Ke */
        $Ke = $ephem['pub'];

        // shared secret: ke * recipientPub
        $S = ECC::mul($ke, $recipientPub);
        if ($S->isInfinity()) throw new \RuntimeException("ECDH failed");

        // derive keystream key from S.x
        $sx = BigInt::i2osp($S->x, 32);
        $nonce = random_bytes(16);

        $cipher = self::xorStream($plaintext, $sx, $nonce);

        return [
            'ephem_pub' => base64_encode(ECC::pubToBytes($Ke)),
            'nonce'     => base64_encode($nonce),
            'cipher'    => base64_encode($cipher),
        ];
    }

    public static function decrypt(array $blob, \GMP $recipientPriv): string
    {
        $Ke = ECC::pubFromBytes(base64_decode($blob['ephem_pub'], true));
        $nonce = base64_decode($blob['nonce'], true);
        $cipher = base64_decode($blob['cipher'], true);

        $S = ECC::mul($recipientPriv, $Ke);
        if ($S->isInfinity()) throw new \RuntimeException("ECDH failed");

        $sx = BigInt::i2osp($S->x, 32);
        return self::xorStream($cipher, $sx, $nonce);
    }

    // SHA256 counter-mode keystream, XOR with input
    private static function xorStream(string $input, string $keyMaterial, string $nonce): string
    {
        $out = "";
        $counter = 0;
        $offset = 0;
        while ($offset < strlen($input)) {
            $block = SHA256::hash($keyMaterial . $nonce . pack("N", $counter), true);
            $take = min(32, strlen($input) - $offset);
            $out .= (substr($input, $offset, $take) ^ substr($block, 0, $take));
            $offset += $take;
            $counter++;
        }
        return $out;
    }
}
