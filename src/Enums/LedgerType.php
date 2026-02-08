<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

use FurqanSiddiqui\Blockchain\Core\Networks\LedgerTypeEnumInterface;

/**
 * Represents different types of blockchain architectures.
 */
enum LedgerType: string implements LedgerTypeEnumInterface
{
    case UTXO = "utxo";
    case EVM = "evm";
}