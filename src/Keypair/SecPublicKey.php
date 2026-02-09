<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Keypair;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;

/**
 * Represents an abstract SEC1 public key in a cryptographic system.
 * Provides methods for handling compressed and expanded formats of the key.
 * Implements the PublicKeyInterface.
 */
readonly class SecPublicKey implements PublicKeyInterface
{
    public ?FixedLengthImmutableBuffer $y;
    public bool $parity;

    /**
     * SecPublicKey constructor.
     */
    public function __construct(
        public FixedLengthImmutableBuffer $x,
        bool|FixedLengthImmutableBuffer   $yOrParity,
    )
    {
        $this->setParity($yOrParity);
        $this->y = $yOrParity instanceof FixedLengthImmutableBuffer ? $yOrParity : null;
    }

    /**
     * @param bool|FixedLengthImmutableBuffer $parity
     * @return void
     */
    private function setParity(bool|FixedLengthImmutableBuffer $parity): void
    {
        if (is_bool($parity)) {
            $this->parity = $parity;
            return;
        }

        $bytes = $parity->bytes();
        $this->parity = (ord($bytes[strlen($bytes) - 1]) & 1) === 1;
    }

    /**
     * @return bool
     */
    public function isCompressed(): bool
    {
        return $this->y === null;
    }

    /**
     * @return string
     */
    public function toCompressed(): string
    {
        return ($this->parity ? "\x03" : "\x02") . $this->x->bytes();
    }

    /**
     * @return string
     */
    public function toExpanded(): string
    {
        if ($this->y === null) {
            throw new \LogicException("Cannot export expanded public key without Y coordinate");
        }

        return "\x04" . $this->x->bytes() . $this->y->bytes();
    }
}