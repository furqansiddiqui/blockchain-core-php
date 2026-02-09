<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\SignatureSchemeInterface;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature;

/**
 * Interface representing the operations for Elliptic Curve Digital Signature Algorithm (ECDSA).
 * Extends the EllipticCurveInterface to provide ECDSA-specific functionality.
 */
interface EcdsaInterface extends SignatureSchemeInterface
{
    public function generatePublicKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): SecPublicKey;

    public function sign(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey,
        ReadableBufferInterface    $msgHash
    ): EcdsaSignature;

    public function verify(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): bool;

    public function recoverPublicKey(
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): SecPublicKey;

    public function findRecoveryId(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): int;
}