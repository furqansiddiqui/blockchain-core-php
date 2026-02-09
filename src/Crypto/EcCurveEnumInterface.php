<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto;

use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;

/**
 * Represents an elliptic curve enumeration that extends the UnitEnum interface.
 * This interface provides methods to retrieve various elliptic curve parameters.
 */
interface EcCurveEnumInterface extends \UnitEnum
{
    /** @return ScalarBitLength */
    public function scalarBitLength(): ScalarBitLength;

    /** @return string Hexadecimal encoded string */
    public function a(): string;

    /** @return string Hexadecimal encoded string */
    public function b(): string;

    /** @return string Hexadecimal encoded string */
    public function p(): string;

    /** @return string Hexadecimal encoded string */
    public function n(): string;

    /** @return string Hexadecimal encoded string */
    public function gx(): string;

    /** @return string Hexadecimal encoded string */
    public function gy(): string;
}