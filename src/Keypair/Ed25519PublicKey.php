<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Keypair;

use Charcoal\Buffers\Types\Bytes32;

/**
 * Ed25519 Public Key.
 * @property-read Bytes32 $bytes
 */
final readonly class Ed25519PublicKey extends EdDSAPublicKey
{
    public function __construct(Bytes32 $bytes)
    {
        parent::__construct($bytes);
    }
}