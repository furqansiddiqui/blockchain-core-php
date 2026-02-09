<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use Charcoal\Buffers\Types\Bytes32;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Codecs\EcdsaDerCodec;
use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;

/**
 * Represents a 256-bit ECDSA (Elliptic Curve Digital Signature Algorithm) signature.
 * @property-read Bytes32 $r
 * @property-read Bytes32 $s
 */
final readonly class EcdsaSignature256 extends EcdsaSignature
{
    public function __construct(Bytes32 $r, Bytes32 $s, ?int $recoveryId = null)
    {
        parent::__construct($r, $s, $recoveryId);
    }

    /**
     * @param ReadableBufferInterface|string $der
     * @return self
     */
    public static function fromDER(ReadableBufferInterface|string $der): self
    {
        [$x, $y] = EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
        return new self(new Bytes32($x), new Bytes32($y));
    }
}