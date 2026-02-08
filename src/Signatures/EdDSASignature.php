<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Encoding\EncodingSchemeInterface;
use FurqanSiddiqui\Blockchain\Core\Enums\Curve;
use FurqanSiddiqui\Blockchain\Core\Enums\SignatureScheme;

/**
 * Represents a digital signature generated using the Edwards-curve Digital Signature Algorithm (EdDSA).
 * Implements the SignatureInterface.
 */
readonly class EdDSASignature implements SignatureInterface
{
    /**
     * EdDSASignature constructor.
     */
    public function __construct(
        private Curve                     $curve,
        public FixedLengthImmutableBuffer $signature,
    )
    {
        if ($this->curve->signatureScheme() !== SignatureScheme::EdDSA) {
            throw new \InvalidArgumentException("Invalid signature scheme: " .
                $this->curve->signatureScheme()->name);
        }

        if ($this->signature->length() !== ($this->curve->scalarLength() * 2)) {
            throw new \LengthException("EdDSA signature length mismatch: " . $this->signature->length() .
                " != " . ($this->curve->scalarLength() * 2));
        }
    }

    /**
     * @return Curve
     */
    public function curve(): Curve
    {
        return $this->curve;
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