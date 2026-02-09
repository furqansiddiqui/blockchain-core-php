<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Curves;

use FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa\EcdsaInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\EllipticCurveInterface;

/**
 * Represents the interface for the Secp256k1 elliptic curve implementation.
 * This interface extends the functionality provided by EllipticCurveInterface
 * and EcdsaInterface, encapsulating operations specific to the Secp256k1 curve.
 */
interface Secp256k1Interface extends EllipticCurveInterface, EcdsaInterface
{
}