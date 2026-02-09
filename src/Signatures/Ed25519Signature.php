<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use Charcoal\Buffers\Types\Bytes32;

/**
 * Ed25519Signature represents an Ed25519 digital signature.
 * @property-read Bytes32 $buffer
 */
final readonly class Ed25519Signature extends EdDSASignature
{
    public function __construct(Bytes32 $signature)
    {
        parent::__construct($signature);
    }
}