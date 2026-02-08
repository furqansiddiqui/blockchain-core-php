<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

/**
 * Represents the format types for compact signature serialization.
 */
enum CompactSignature
{
    case RS;
    case RSV;
    case VRS;
}