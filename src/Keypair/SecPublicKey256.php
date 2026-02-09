<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Keypair;

use Charcoal\Buffers\Types\Bytes32;

/**
 * Represents a 256-bit elliptic curve public key.
 * @property-read Bytes32 $x
 * @property-read Bytes32|null $y
 */
final readonly class SecPublicKey256 extends SecPublicKey
{
    public function __construct(Bytes32 $x, bool|Bytes32 $yOrParity)
    {
        parent::__construct($x, $yOrParity);
    }
}