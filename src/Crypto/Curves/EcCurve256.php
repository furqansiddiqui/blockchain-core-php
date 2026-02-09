<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Curves;

use Charcoal\Buffers\Types\Bytes32;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecc\AbstractWeierstrassCurve;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecc\EcPoint;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey256;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature256;

/**
 * Represents the secp256r1 elliptic curve and provides methods for key and signature handling.
 */
readonly class EcCurve256 extends AbstractWeierstrassCurve
{
    /**
     * @param EcPoint $point
     * @return SecPublicKey256
     */
    protected function createPublicKeyFromPoint(EcPoint $point): SecPublicKey256
    {
        return new SecPublicKey256(
            Bytes32::setPadded(gmp_export($point->x, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)),
            Bytes32::setPadded(gmp_export($point->y, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)),
        );
    }

    /**
     * @param \GMP $r
     * @param \GMP $s
     * @return EcdsaSignature256
     */
    protected function createSignatureInstance(\GMP $r, \GMP $s): EcdsaSignature256
    {
        return new EcdsaSignature256(
            Bytes32::setPadded(gmp_export($r, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)),
            Bytes32::setPadded(gmp_export($s, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)),
            recoveryId: null
        );
    }

    /**
     * @param \GMP $x
     * @param bool $yParity
     * @return SecPublicKey256
     */
    protected function createCompressedPublicKey(\GMP $x, bool $yParity): SecPublicKey256
    {
        return new SecPublicKey256(
            Bytes32::setPadded(gmp_export($x, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)),
            $yParity
        );
    }
}