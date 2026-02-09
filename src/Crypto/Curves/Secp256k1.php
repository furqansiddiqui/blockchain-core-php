<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Curves;

use Charcoal\Buffers\Types\Bytes32;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Enums\EcCurve;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey256;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature256;

/**
 * This class provides an implementation of the Secp256k1 curve for elliptic curve cryptography.
 * It includes methods for validating private keys, generating public keys, signing messages,
 * verifying signatures, and recovering public keys from signatures.
 */
final readonly class Secp256k1 implements Secp256k1Interface
{
    private EcCurve256 $curve;

    /**
     * Secp256k1 constructor.
     */
    public function __construct()
    {
        $this->curve = new EcCurve256(EcCurve::Secp256k1, "sha256");
    }

    /**
     * @param Bytes32 $privateKey
     * @return void
     */
    public function validatePrivateKey(
        #[\SensitiveParameter] Bytes32 $privateKey
    ): void
    {
        $this->curve->validatePrivateKey($privateKey);
    }

    /**
     * @param Bytes32 $privateKey
     * @return SecPublicKey256
     */
    public function generatePublicKey(
        #[\SensitiveParameter]
        Bytes32 $privateKey
    ): SecPublicKey256
    {
        /** @var SecPublicKey256 */
        return $this->curve->generatePublicKey($privateKey);
    }

    /**
     * @param Bytes32 $privateKey
     * @param Bytes32 $msgHash
     * @return EcdsaSignature256
     */
    public function sign(
        #[\SensitiveParameter]
        Bytes32 $privateKey,
        Bytes32 $msgHash
    ): EcdsaSignature256
    {
        /** @var EcdsaSignature256 */
        return $this->curve->sign($privateKey, $msgHash, randomK: null);
    }

    /**
     * @param Bytes32 $privateKey
     * @param Bytes32 $msgHash
     * @param ReadableBufferInterface $randomK
     * @return EcdsaSignature256
     */
    public function signWithNonce(
        #[\SensitiveParameter]
        Bytes32                 $privateKey,
        Bytes32                 $msgHash,
        ReadableBufferInterface $randomK
    ): EcdsaSignature256
    {
        /** @var EcdsaSignature256 */
        return $this->curve->sign($privateKey, $msgHash, randomK: null);
    }

    /**
     * @param SecPublicKey256 $publicKey
     * @param EcdsaSignature256 $signature
     * @param Bytes32 $msgHash
     * @return bool
     */
    public function verify(
        SecPublicKey256   $publicKey,
        EcdsaSignature256 $signature,
        Bytes32           $msgHash
    ): bool
    {
        return $this->curve->verify($publicKey, $signature, $msgHash);
    }

    /**
     * @param EcdsaSignature256 $signature
     * @param Bytes32 $msgHash
     * @param int|null $recoveryId
     * @return SecPublicKey256
     */
    public function recoverPublicKey(
        EcdsaSignature256 $signature,
        Bytes32           $msgHash,
        ?int              $recoveryId = null
    ): SecPublicKey256
    {
        /** @var SecPublicKey256 */
        return $this->curve->recoverPublicKey($signature, $msgHash, $recoveryId);
    }
}