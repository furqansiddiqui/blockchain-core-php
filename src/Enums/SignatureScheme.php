<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

/**
 * This enum is used to define supported cryptographic signature schemes,
 * allowing for the selection of a specific algorithm when handling
 * digital signatures.
 */
enum SignatureScheme: string
{
    case ECDSA = "ecdsa";
    case EdDSA = "eddsa";
}