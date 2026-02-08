<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Encoding\EncodingSchemeInterface;

/**
 * Represents a digital signature generated using the Edwards-curve Digital Signature Algorithm (EdDSA).
 * Implements the SignatureInterface.
 */
readonly abstract class EdDSASignature implements SignatureInterface
{
    /**
     * EdDSASignature constructor.
     */
    public function __construct(
        public FixedLengthImmutableBuffer $signature,
    )
    {
    }

    /**
     * @return string
     */
    public function bytes(): string
    {
        return $this->signature->bytes();
    }

    /**
     * @param EncodingSchemeInterface $scheme
     * @return string
     */
    public function encode(EncodingSchemeInterface $scheme): string
    {
        return $this->signature->encode($scheme);
    }
}