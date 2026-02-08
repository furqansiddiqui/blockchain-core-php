<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

/**
 * Represents a set of cryptographic curves used in elliptic-curve cryptography.
 */
enum Curve: string
{
    case Secp256k1 = "secp256k1";
    case Ed25519 = "ed25519";

    /**
     * @return SignatureScheme
     */
    public function signatureScheme(): SignatureScheme
    {
        return match ($this) {
            self::Secp256k1 => SignatureScheme::ECDSA,
            self::Ed25519 => SignatureScheme::EdDSA
        };
    }

    /**
     * @return int
     */
    public function scalarLength(): int
    {
        return match ($this) {
            self::Secp256k1,
            self::Ed25519 => 32
        };
    }
}