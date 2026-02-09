<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;

/**
 * Interface that defines operations for elliptic curve cryptography.
 */
interface EllipticCurveInterface
{
    public function scalarBitLength(): ScalarBitLength;

    public function validatePrivateKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): bool;
}