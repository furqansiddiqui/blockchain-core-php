<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Keypair\PublicKeyInterface;
use FurqanSiddiqui\Blockchain\Core\Signatures\SignatureInterface;

/**
 * Defines the contract for signature schemes, providing methods
 * to interact with elliptic curves, generate public keys, and create
 * cryptographic signatures.
 */
interface SignatureSchemeInterface
{
    public function generatePublicKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): PublicKeyInterface;

    public function sign(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey,
        ReadableBufferInterface    $msgHash
    ): SignatureInterface;
}