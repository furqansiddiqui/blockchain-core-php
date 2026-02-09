<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Keypair;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Encoding\EncodingSchemeInterface;

/**
 * This class provides the functionality to hold and retrieve the key bytes
 * of an EdDSA public key in an immutable fashion.
 */
readonly class EdDSAPublicKey implements PublicKeyInterface
{
    public function __construct(
        public FixedLengthImmutableBuffer $buffer
    )
    {
    }

    /**
     * @return string
     */
    public function bytes(): string
    {
        return $this->buffer->bytes();
    }

    /**
     * @param EncodingSchemeInterface $scheme
     * @return string
     */
    public function encode(EncodingSchemeInterface $scheme): string
    {
        return $this->buffer->encode($scheme);
    }
}