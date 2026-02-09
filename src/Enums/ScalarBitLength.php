<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

/**
 * Represents the bit length of a scalar value used in cryptographic operations.
 */
enum ScalarBitLength: int
{
    case Bits256 = 256;
    case Bits384 = 384;
    case Bits521 = 521;
}