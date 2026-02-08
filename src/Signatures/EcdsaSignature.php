<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Encoding\EncodingSchemeInterface;
use FurqanSiddiqui\Blockchain\Core\Enums\CompactSignature;
use FurqanSiddiqui\Blockchain\Core\Enums\Curve;
use FurqanSiddiqui\Blockchain\Core\Enums\SignatureScheme;

/**
 * Represents an ECDSA (Elliptic Curve Digital Signature Algorithm) signature.
 * It consists of the components `r` and `s`, which are fixed-length immutable buffers,
 * and an optional `recoveryId` for use cases such as signature recovery.
 */
readonly class EcdsaSignature implements SignatureInterface
{
    /**
     * EcdsaSignature constructor.
     */
    public function __construct(
        private Curve                     $curve,
        public FixedLengthImmutableBuffer $r,
        public FixedLengthImmutableBuffer $s,
        public ?int                       $recoveryId = null
    )
    {
        if ($this->curve->signatureScheme() !== SignatureScheme::ECDSA) {
            throw new \InvalidArgumentException("Invalid signature scheme: " .
                $this->curve->signatureScheme()->name);
        }

        if ($r->length() !== $this->curve->scalarLength()) {
            throw new \LengthException("ECDSA signature R length mismatch: " . $r->length() .
                " != " . $this->curve->scalarLength());
        }

        if ($s->length() !== $this->curve->scalarLength()) {
            throw new \LengthException("ECDSA signature S length mismatch: " . $s->length() .
                " != " . $this->curve->scalarLength());
        }

        if (is_int($recoveryId) && ($recoveryId < 0 || $recoveryId > 255)) {
            throw new \InvalidArgumentException("Invalid recovery ID: " . $recoveryId);
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
     * @param CompactSignature $format
     * @param EncodingSchemeInterface|null $encoding
     * @return string
     */
    public function toCompact(
        CompactSignature         $format = CompactSignature::RS,
        ?EncodingSchemeInterface $encoding = null
    ): string
    {
        if ($format !== CompactSignature::RS && $this->recoveryId === null) {
            throw new \InvalidArgumentException("Cannot export signature without recovery ID");
        }

        $compact = match ($format) {
            CompactSignature::RSV => $this->r->bytes() . $this->s->bytes() . chr($this->recoveryId),
            CompactSignature::RS => $this->r->bytes() . $this->s->bytes(),
            CompactSignature::VRS => chr($this->recoveryId) . $this->r->bytes() . $this->s->bytes(),
        };

        return $encoding ? $encoding->encode($compact) : $compact;
    }
}