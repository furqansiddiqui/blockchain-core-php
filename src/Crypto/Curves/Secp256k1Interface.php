<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Curves;

use Charcoal\Buffers\Types\Bytes32;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey256;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature256;

/**
 * Interface for interacting with the Secp256k1 elliptic curve algorithm.
 * Provides methods for validating keys, signing messages, verifying signatures,
 * and recovering public keys.
 */
interface Secp256k1Interface
{
    /**
     * Validate the given private key.
     */
    public function validatePrivateKey(
        #[\SensitiveParameter]
        Bytes32 $privateKey
    ): void;

    /**
     * Generate a public key from the given private key.
     */
    public function generatePublicKey(
        #[\SensitiveParameter]
        Bytes32 $privateKey
    ): SecPublicKey256;

    /**
     * Sign the given message hash with the given private key.
     */
    public function sign(
        #[\SensitiveParameter]
        Bytes32 $privateKey,
        Bytes32 $msgHash
    ): EcdsaSignature256;

    /**
     * Sign the given message hash with the given private key and nonce.
     */
    public function signWithNonce(
        #[\SensitiveParameter]
        Bytes32 $privateKey,
        Bytes32 $msgHash,
        Bytes32 $randomK
    ): EcdsaSignature256;

    /**
     * Verify the given signature against the given message hash and public key.
     */
    public function verify(
        SecPublicKey256   $publicKey,
        EcdsaSignature256 $signature,
        Bytes32           $msgHash
    ): bool;

    /**
     * Recover the public key from the given signature, message hash, and recovery ID.
     */
    public function recoverPublicKey(
        EcdsaSignature256 $signature,
        Bytes32           $msgHash,
        ?int              $recoveryId = null
    ): SecPublicKey256;
}