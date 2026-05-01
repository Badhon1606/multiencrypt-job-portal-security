<?php
// crypto/ECC.php
declare(strict_types=1);

require_once __DIR__ . "/BigInt.php";

final class ECPoint
{
    public ?\GMP $x;
    public ?\GMP $y;

    public function __construct(?\GMP $x, ?\GMP $y) { $this->x=$x; $this->y=$y; }
    public function isInfinity(): bool { return $this->x === null || $this->y === null; }
}

final class ECC
{
    // secp256k1 parameters
    public static function p(): \GMP { return BigInt::fromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); }
    public static function a(): \GMP { return gmp_init("0",10); }
    public static function b(): \GMP { return gmp_init("7",10); }
    public static function n(): \GMP { return BigInt::fromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); }

    public static function G(): ECPoint
    {
        $gx = BigInt::fromHex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
        $gy = BigInt::fromHex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        return new ECPoint($gx, $gy);
    }

    public static function keygen(): array
    {
        $d = BigInt::randRange(gmp_init(1), gmp_sub(self::n(), 1));
        $Q = self::mul($d, self::G());
        return ['priv'=>$d, 'pub'=>$Q];
    }

    public static function isOnCurve(ECPoint $P): bool
    {
        if ($P->isInfinity()) return true;
        $p = self::p();
        $x = $P->x; $y = $P->y;
        $left = gmp_mod(gmp_mul($y, $y), $p);
        $right = gmp_mod(gmp_add(gmp_add(gmp_powm($x, gmp_init(3), $p), gmp_mul(self::a(), $x)), self::b()), $p);
        return gmp_cmp($left, $right) === 0;
    }

    public static function add(ECPoint $P, ECPoint $Q): ECPoint
    {
        $p = self::p();
        if ($P->isInfinity()) return $Q;
        if ($Q->isInfinity()) return $P;

        $x1=$P->x; $y1=$P->y; $x2=$Q->x; $y2=$Q->y;

        if (gmp_cmp($x1, $x2) === 0) {
            if (gmp_cmp(gmp_mod(gmp_add($y1, $y2), $p), gmp_init(0)) === 0) {
                return new ECPoint(null, null); // infinity
            }
            return self::dbl($P);
        }

        $lambda = gmp_mod(
            gmp_mul(gmp_sub($y2, $y1), BigInt::modInv(gmp_sub($x2, $x1), $p)),
            $p
        );

        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_mul($lambda, $lambda), $x1), $x2), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1, $x3)), $y1), $p);

        return new ECPoint($x3, $y3);
    }

    public static function dbl(ECPoint $P): ECPoint
    {
        $p = self::p();
        if ($P->isInfinity()) return $P;

        $x1=$P->x; $y1=$P->y;
        if (gmp_cmp($y1, gmp_init(0)) === 0) return new ECPoint(null, null);

        $num = gmp_add(gmp_mul(gmp_init(3), gmp_mul($x1,$x1)), self::a());
        $den = gmp_mul(gmp_init(2), $y1);
        $lambda = gmp_mod(gmp_mul($num, BigInt::modInv($den, $p)), $p);

        $x3 = gmp_mod(gmp_sub(gmp_mul($lambda,$lambda), gmp_mul(gmp_init(2), $x1)), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($lambda, gmp_sub($x1,$x3)), $y1), $p);

        return new ECPoint($x3, $y3);
    }

    public static function mul(\GMP $k, ECPoint $P): ECPoint
    {
        $n = self::n();
        $k = gmp_mod($k, $n);
        $R = new ECPoint(null, null); // infinity
        $addend = $P;

        $bin = gmp_strval($k, 2);
        for ($i=0; $i<strlen($bin); $i++) {
            $R = self::dbl($R);
            if ($bin[$i] === '1') {
                $R = self::add($R, $addend);
            }
        }
        return $R;
    }

    // Serialize pubkey (uncompressed): 0x04 || x(32) || y(32)
    public static function pubToBytes(ECPoint $Q): string
    {
        if ($Q->isInfinity()) throw new \RuntimeException("Infinity point cannot serialize");
        $x = BigInt::i2osp($Q->x, 32);
        $y = BigInt::i2osp($Q->y, 32);
        return "\x04".$x.$y;
    }

    public static function pubFromBytes(string $b): ECPoint
    {
        if (strlen($b) !== 65 || $b[0] !== "\x04") throw new \RuntimeException("Invalid uncompressed pubkey");
        $x = BigInt::os2ip(substr($b,1,32));
        $y = BigInt::os2ip(substr($b,33,32));
        $Q = new ECPoint($x,$y);
        if (!self::isOnCurve($Q)) throw new \RuntimeException("Pubkey not on curve");
        return $Q;
    }
}
