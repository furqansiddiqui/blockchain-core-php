<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Ecc;

/**
 * A utility class providing mathematical operations for elliptic curve computations.
 */
abstract readonly class EcMath
{
    /**
     * @param \GMP $a
     * @param \GMP $p
     * @return array{0:\GMP,1:\GMP}|null
     * */
    public static function sqrt(\GMP $a, \GMP $p): ?array
    {
        $a = gmp_mod($a, $p);
        if (gmp_cmp($a, 0) === 0) {
            return [gmp_init(0, 10), gmp_init(0, 10)];
        }

        if (gmp_legendre($a, $p) !== 1) {
            return null;
        }

        $pMod4 = gmp_intval(gmp_mod($p, 4));
        if ($pMod4 === 3) {
            $r = gmp_powm($a, gmp_div_q(gmp_add($p, 1), 4), $p);
            return [$r, gmp_mod(gmp_sub($p, $r), $p)];
        }

        $pMod8 = gmp_intval(gmp_mod($p, 8));
        if ($pMod8 === 5) {
            $r = gmp_powm($a, gmp_div_q(gmp_add($p, 3), 8), $p);
            if (gmp_cmp(gmp_mod(gmp_mul($r, $r), $p), $a) !== 0) {
                $i = gmp_powm(gmp_init(2, 10), gmp_div_q(gmp_sub($p, 1), 4), $p);
                $r = gmp_mod(gmp_mul($r, $i), $p);
            }
            return [$r, gmp_mod(gmp_sub($p, $r), $p)];
        }

        return self::tonelliShanks($a, $p);
    }


    /**
     * @param \GMP $n
     * @param \GMP $p
     * @return array{0: \GMP, 1: \GMP}|null
     */
    private static function tonelliShanks(\GMP $n, \GMP $p): ?array
    {
        $q = gmp_sub($p, 1);
        $s = 0;
        while (gmp_cmp(gmp_mod($q, 2), 0) === 0) {
            $q = gmp_div_q($q, 2);
            $s++;
        }

        $z = gmp_init(2, 10);
        while (gmp_legendre($z, $p) !== -1) {
            $z = gmp_add($z, 1);
        }

        $c = gmp_powm($z, $q, $p);
        $r = gmp_powm($n, gmp_div_q(gmp_add($q, 1), 2), $p);
        $t = gmp_powm($n, $q, $p);
        $m = $s;

        while (gmp_cmp($t, 1) !== 0) {
            $i = 1;
            $t2i = gmp_mod(gmp_mul($t, $t), $p);
            while ($i < $m && gmp_cmp($t2i, 1) !== 0) {
                $t2i = gmp_mod(gmp_mul($t2i, $t2i), $p);
                $i++;
            }
            if ($i === $m) {
                return null;
            }

            $b = $c;
            for ($j = 0; $j < ($m - $i - 1); $j++) {
                $b = gmp_mod(gmp_mul($b, $b), $p);
            }

            $r = gmp_mod(gmp_mul($r, $b), $p);
            $t = gmp_mod(gmp_mul($t, gmp_mod(gmp_mul($b, $b), $p)), $p);
            $c = gmp_mod(gmp_mul($b, $b), $p);
            $m = $i;
        }

        return [$r, gmp_mod(gmp_sub($p, $r), $p)];
    }
}