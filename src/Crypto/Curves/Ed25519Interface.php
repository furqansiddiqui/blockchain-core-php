<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Curves;

use FurqanSiddiqui\Blockchain\Core\Crypto\EdDSA\EdDSAInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\EllipticCurveInterface;

/**
 * This interface extends functionality from both the EllipticCurveInterface
 * and the EdDSAInterface, providing a specialized contract for implementing
 * the Ed25519 signature scheme based on elliptic curve cryptography.
 */
interface Ed25519Interface extends EllipticCurveInterface, EdDSAInterface
{
}