<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Keypair;

use Charcoal\Buffers\Types\Bytes32;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;

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

    /**
     * @param string|ReadableBufferInterface $publicKey
     * @return self
     */
    public static function fromBytes(string|ReadableBufferInterface $publicKey): self
    {
        $publicKey = $publicKey instanceof ReadableBufferInterface ? $publicKey->bytes() : $publicKey;
        $publicKeyLen = strlen($publicKey);
        if ($publicKeyLen === 0) {
            throw new \InvalidArgumentException("Empty public key");
        }

        // Uncompressed Public Keys
        if ($publicKey[0] === "\x04") {
            if ($publicKeyLen !== 65) {
                throw new \LengthException("Expected 65 bytes for uncompressed public key, got " .
                    $publicKeyLen . " bytes");
            }

            return new self(new Bytes32(substr($publicKey, 1, 32)), new Bytes32(substr($publicKey, 33, 32)));
        }

        // Compressed Public Keys
        if (in_array($publicKey[0], ["\x02", "\x03"], true)) {
            if ($publicKeyLen !== 33) {
                throw new \LengthException("Expected 33 bytes for compressed public key, got " .
                    $publicKeyLen . " bytes");
            }

            return new self(new Bytes32(substr($publicKey, 1, 32)), $publicKey[0] === "\x03");
        }

        throw new \InvalidArgumentException("Invalid public key");
    }
}