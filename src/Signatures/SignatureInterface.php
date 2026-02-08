<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Signatures;

use FurqanSiddiqui\Blockchain\Core\Enums\Curve;

/**
 * Defines the structure for cryptographic signature functionality,
 * including operations related to mathematical curves.
 */
interface SignatureInterface
{
    public function curve(): Curve;
}