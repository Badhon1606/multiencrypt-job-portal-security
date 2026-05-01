<?php
// crypto/RSA.php
declare(strict_types=1);

require_once __DIR__ . "/BigInt.php";
require_once __DIR__ . "/SHA256.php";

final class RSAKeyPair
{
    public \GMP $n; public \GMP $e; public \GMP $d;
    public int $bits;

    public function __construct(\GMP $n, \GMP $e, \GMP $d, int $bits)
    { $this->n=$n; $this->e=$e; $this->d=$d; $this->bits=$bits; }

    public function public(): array { return ['n'=>BigInt::toHex($this->n), 'e'=>BigInt::toHex($this->e), 'bits'=>$this->bits]; }
    public function private(): array { return ['n'=>BigInt::toHex($this->n), 'd'=>BigInt::toHex($this->d), 'bits'=>$this->bits]; }
}

final class RSA
{
    // 2048 for real use; for fast testing you can use 1024
    public static function generate(int $bits = 2048, int $eVal = 65537): RSAKeyPair
    {
        $e = gmp_init((string)$eVal, 10);
        $pBits = intdiv($bits, 2);
        $qBits = $bits - $pBits;

        while (true) {
            $p = BigInt::genPrime($pBits);
            $q = BigInt::genPrime($qBits);
            if (gmp_cmp($p, $q) === 0) continue;

            $n = gmp_mul($p, $q);
            $phi = gmp_mul(gmp_sub($p,1), gmp_sub($q,1));

            if (gmp_cmp(BigInt::gcd($e, $phi), 1) !== 0) continue;

            $d = BigInt::modInv($e, $phi);
            return new RSAKeyPair($n, $e, $d, $bits);
        }
    }

    // OAEP parameters: SHA256 => hLen=32
    public static function encryptOAEP(string $msg, array $pub, string $label = ""): string
    {
        $n = BigInt::fromHex($pub['n']);
        $e = BigInt::fromHex($pub['e']);
        $k = intdiv((int)$pub['bits'] + 7, 8);
        $hLen = 32;

        if (strlen($msg) > $k - 2*$hLen - 2) {
            throw new \RuntimeException("Message too long for RSA-OAEP");
        }

        $lHash = SHA256::hash($label, true);
        $ps = str_repeat("\x00", $k - strlen($msg) - 2*$hLen - 2);
        $db = $lHash . $ps . "\x01" . $msg;

        $seed = random_bytes($hLen);
        $dbMask = self::mgf1($seed, $k - $hLen - 1);
        $maskedDB = $db ^ $dbMask;

        $seedMask = self::mgf1($maskedDB, $hLen);
        $maskedSeed = $seed ^ $seedMask;

        $em = "\x00" . $maskedSeed . $maskedDB;

        $m = BigInt::os2ip($em);
        $c = BigInt::modPow($m, $e, $n);
        return BigInt::i2osp($c, $k);
    }

    public static function decryptOAEP(string $ct, array $priv, string $label = ""): string
    {
        $n = BigInt::fromHex($priv['n']);
        $d = BigInt::fromHex($priv['d']);
        $k = intdiv((int)$priv['bits'] + 7, 8);
        $hLen = 32;

        if (strlen($ct) !== $k) throw new \RuntimeException("Ciphertext length invalid");

        $c = BigInt::os2ip($ct);
        $m = BigInt::modPow($c, $d, $n);
        $em = BigInt::i2osp($m, $k);

        if ($em[0] !== "\x00") throw new \RuntimeException("OAEP decode error");

        $maskedSeed = substr($em, 1, $hLen);
        $maskedDB   = substr($em, 1+$hLen);

        $seedMask = self::mgf1($maskedDB, $hLen);
        $seed = $maskedSeed ^ $seedMask;

        $dbMask = self::mgf1($seed, $k - $hLen - 1);
        $db = $maskedDB ^ $dbMask;

        $lHash = SHA256::hash($label, true);
        $lHash2 = substr($db, 0, $hLen);
        if (!hash_equals($lHash, $lHash2)) throw new \RuntimeException("OAEP label hash mismatch");

        $rest = substr($db, $hLen);
        $pos = strpos($rest, "\x01");
        if ($pos === false) throw new \RuntimeException("OAEP decode error");
        return substr($rest, $pos + 1);
    }

    private static function mgf1(string $seed, int $maskLen): string
    {
        $hLen = 32;
        $t = "";
        $counter = 0;
        while (strlen($t) < $maskLen) {
            $c = pack("N", $counter);
            $t .= SHA256::hash($seed . $c, true);
            $counter++;
        }
        return substr($t, 0, $maskLen);
    }
}
