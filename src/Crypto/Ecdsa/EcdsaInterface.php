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
    /**
     * Generate a public key from the given private key.
     */
    public function generatePublicKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): SecPublicKey;

    /**
     * Sign the given message hash with the given private key.
     */
    public function sign(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey,
        ReadableBufferInterface    $msgHash,
        ?ReadableBufferInterface   $randomK = null
    ): EcdsaSignature;

    /**
     * Verify the given signature against the given message hash and public key.
     */
    public function verify(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): bool;

    /**
     * Recover the public key from the given signature, message hash, and recovery ID.
     */
    public function recoverPublicKey(
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash,
        ?int                    $recoveryId = null
    ): SecPublicKey;

    /**
     * Expand the given compressed public key into its uncompressed form.
     */
    public function expandPublicKey(
        SecPublicKey $publicKey
    ): SecPublicKey;

    /**
     * Find the recovery ID for the given signature, message hash, and public key.
     */
    public function findRecoveryId(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): int;
}