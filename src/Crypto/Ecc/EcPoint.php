<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Ecc;

/**
 * Represents a point on an elliptic curve defined by the Weierstrass equation.
 * This class provides methods for point doubling, addition, scalar multiplication,
 * and curve point validation.
 */
final readonly class EcPoint
{
    public function __construct(
        public AbstractWeierstrassCurve $curve,
        public \GMP                     $x,
        public \GMP                     $y
    )
    {
    }

    /**
     * @return EcPoint
     */
    public function double(): EcPoint
    {
        $p = $this->curve->p;
        if (gmp_cmp($this->y, 0) === 0) {
            throw new \LogicException("Point at infinity");
        }

        $twoY = gmp_mod(gmp_mul(2, $this->y), $p);
        $inv = gmp_invert($twoY, $p);
        if ($inv === false) {
            throw new \LogicException("Point at infinity");
        }

        $num = gmp_add(gmp_mul(3, gmp_pow($this->x, 2)), $this->curve->a);
        $slope = gmp_mod(gmp_mul($num, $inv), $p);
        $x3 = gmp_mod(gmp_sub(gmp_pow($slope, 2), gmp_mul(2, $this->x)), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($this->x, $x3)), $this->y), $p);
        return new EcPoint($this->curve, $x3, $y3);
    }

    /**
     * @param EcPoint $p2
     * @return EcPoint
     */
    public function add(EcPoint $p2): EcPoint
    {
        $p = $this->curve->p;
        if (gmp_cmp($this->x, $p2->x) === 0 && gmp_cmp($this->y, $p2->y) === 0) {
            return $this->double();
        }

        if (gmp_cmp($this->x, $p2->x) === 0 && gmp_cmp(gmp_mod(gmp_add($this->y, $p2->y), $p), 0) === 0) {
            throw new \LogicException("Point at infinity");
        }

        $dx = gmp_mod(gmp_sub($this->x, $p2->x), $p);
        $inv = gmp_invert($dx, $p);
        if ($inv === false) {
            throw new \LogicException("Point at infinity");
        }

        $slope = gmp_mod(gmp_mul(gmp_sub($this->y, $p2->y), $inv), $p);
        $x3 = gmp_mod(gmp_sub(gmp_pow($slope, 2), gmp_add($this->x, $p2->x)), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($this->x, $x3)), $this->y), $p);
        return new EcPoint($this->curve, $x3, $y3);
    }

    /**
     * @param \GMP $k
     * @return self
     */
    public function mul(\GMP $k): self
    {
        if (gmp_cmp($k, 1) < 0) {
            throw new \InvalidArgumentException("Scalar must be >= 1");
        }

        $bits = gmp_strval($k, 2);
        $acc = null;
        $add = $this;
        for ($i = strlen($bits) - 1; $i >= 0; $i--) {
            if ($bits[$i] === "1") {
                $acc = $acc ? $acc->add($add) : $add;
            }

            $add = $add->double();
        }

        if ($acc === null) {
            throw new \LogicException("Point at infinity");
        }

        if (!$acc->validate()) {
            throw new \UnexpectedValueException("Resulting point not on curve");
        }

        return $acc;
    }

    /**
     * @return bool
     */
    public function validate(): bool
    {
        $p = $this->curve->p;
        $x3 = gmp_powm($this->x, 3, $p);
        $ax = gmp_mod(gmp_mul($this->curve->a, $this->x), $p);
        $rhs = gmp_mod(gmp_add(gmp_add($x3, $ax), $this->curve->b), $p);
        $lhs = gmp_powm($this->y, 2, $p);
        return gmp_cmp($lhs, $rhs) === 0;
    }
}