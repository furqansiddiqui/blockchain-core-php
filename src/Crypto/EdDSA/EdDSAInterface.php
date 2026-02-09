<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\EdDSA;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\SignatureSchemeInterface;
use FurqanSiddiqui\Blockchain\Core\Keypair\EdDSAPublicKey;
use FurqanSiddiqui\Blockchain\Core\Signatures\EdDSASignature;

/**
 * Interface representing the EdDSA cryptographic signature scheme.
 * Defines methods for generating public keys, signing messages,
 * and verifying signatures using the EdDSA algorithm.
 */
interface EdDSAInterface extends SignatureSchemeInterface
{
    public function generatePublicKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): EdDSAPublicKey;

    public function sign(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey,
        ReadableBufferInterface    $msgHash
    ): EdDSASignature;

    public function verify(
        EdDSAPublicKey          $publicKey,
        EdDSASignature          $signature,
        ReadableBufferInterface $msgHash
    ): bool;
}