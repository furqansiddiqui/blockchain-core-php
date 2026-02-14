<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Derivation;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Buffers\Types\Bytes32;

/**
 * Provides functionality for deriving child keys using HMAC.
 */
final class ChildKeyDerivation
{
    /**
     * A fully deterministic key derivation function using HMAC-SHA512.
     */
    public static function deriveHmac(
        FixedLengthImmutableBuffer $key,
        string                     $childPath
    ): FixedLengthImmutableBuffer
    {
        if (!$childPath) {
            throw new \InvalidArgumentException("Child path cannot be empty");
        }

        $frameFqcn = $key::class;
        $frameSize = $key->length();
        if ($frameSize > 64) {
            throw new \InvalidArgumentException("Key frame size must be <= 64 bytes");
        }

        $childKey = substr(hash_hmac("sha512", $childPath, $key->bytes(), true), 0, $frameSize);
        return new $frameFqcn($childKey);
    }

    /**
     * A fully deterministic key derivation of 32 bytes using HMAC-SHA512.
     */
    public static function deriveHmac32(Bytes32 $key, string $childPath): Bytes32
    {
        /** @var Bytes32 */
        return self::deriveHmac($key, $childPath);
    }
}