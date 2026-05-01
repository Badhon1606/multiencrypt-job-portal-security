<?php
// crypto/BigInt.php
declare(strict_types=1);

final class BigInt
{
    public static function g($x): \GMP
    {
        if ($x instanceof \GMP) return $x;
        if (is_int($x)) return gmp_init((string)$x, 10);
        if (is_string($x)) return gmp_init($x, 0);
        throw new \InvalidArgumentException("Unsupported BigInt input");
    }

    public static function toHex(\GMP $x): string
    {
        $h = gmp_strval($x, 16);
        return (strlen($h) % 2 === 1) ? "0".$h : $h;
    }

    public static function fromHex(string $hex): \GMP
    {
        $hex = strtolower($hex);
        if (str_starts_with($hex, "0x")) $hex = substr($hex, 2);
        if ($hex === "") $hex = "0";
        return gmp_init($hex, 16);
    }

    public static function modPow(\GMP $a, \GMP $e, \GMP $n): \GMP
    {
        return gmp_powm($a, $e, $n);
    }

    public static function gcd(\GMP $a, \GMP $b): \GMP
    {
        return gmp_gcd($a, $b);
    }

    public static function modInv(\GMP $a, \GMP $n): \GMP
    {
        $inv = gmp_invert($a, $n);
        if ($inv === false) {
            throw new \RuntimeException("No modular inverse");
        }
        return $inv;
    }

    public static function randBits(int $bits): \GMP
    {
        if ($bits <= 0) return gmp_init("0", 10);
        $bytes = intdiv($bits + 7, 8);
        $raw = random_bytes($bytes);

        // Ensure top bit set and odd (for prime candidates)
        $raw[0] = $raw[0] | chr(1 << (($bits - 1) % 8));
        $raw[$bytes - 1] = $raw[$bytes - 1] | "\x01";

        return self::fromHex(bin2hex($raw));
    }

    // Miller-Rabin primality test
    public static function isProbablePrime(\GMP $n, int $rounds = 32): bool
    {
        if (gmp_cmp($n, 2) < 0) return false;
        if (gmp_cmp($n, 2) === 0 || gmp_cmp($n, 3) === 0) return true;
        if (gmp_intval(gmp_mod($n, 2)) === 0) return false;

        // write n-1 = d * 2^s
        $d = gmp_sub($n, 1);
        $s = 0;
        while (gmp_intval(gmp_mod($d, 2)) === 0) {
            $d = gmp_div_q($d, 2);
            $s++;
        }

        $nMinus1 = gmp_sub($n, 1);
        for ($i = 0; $i < $rounds; $i++) {
            // a in [2, n-2]
            $a = self::randRange(gmp_init(2), gmp_sub($n, 2));
            $x = gmp_powm($a, $d, $n);

            if (gmp_cmp($x, 1) === 0 || gmp_cmp($x, $nMinus1) === 0) continue;

            $continueOuter = false;
            for ($r = 1; $r < $s; $r++) {
                $x = gmp_powm($x, gmp_init(2), $n);
                if (gmp_cmp($x, $nMinus1) === 0) {
                    $continueOuter = true;
                    break;
                }
            }
            if ($continueOuter) continue;

            return false;
        }
        return true;
    }

    public static function genPrime(int $bits): \GMP
    {
        while (true) {
            $cand = self::randBits($bits);
            if (self::isProbablePrime($cand)) return $cand;
        }
    }

    public static function randRange(\GMP $min, \GMP $max): \GMP
    {
        // inclusive range
        if (gmp_cmp($min, $max) > 0) throw new \InvalidArgumentException("min>max");
        $range = gmp_add(gmp_sub($max, $min), 1);
        $bits = strlen(gmp_strval($range, 2));
        do {
            $x = self::randBits($bits);
        } while (gmp_cmp($x, $range) >= 0);
        return gmp_add($min, $x);
    }

    public static function i2osp(\GMP $x, int $len): string
    {
        $hex = self::toHex($x);
        $bin = hex2bin($hex);
        if ($bin === false) $bin = "";
        if (strlen($bin) > $len) {
            // truncate (shouldn't happen in correct use)
            $bin = substr($bin, -$len);
        }
        return str_pad($bin, $len, "\x00", STR_PAD_LEFT);
    }

    public static function os2ip(string $x): \GMP
    {
        return self::fromHex(bin2hex($x));
    }
}
