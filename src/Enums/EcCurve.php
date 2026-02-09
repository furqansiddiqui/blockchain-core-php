<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Enums;

use FurqanSiddiqui\Blockchain\Core\Crypto\EcCurveEnumInterface;

/**
 * Enumeration representing standard elliptic curves.
 * This class defines constants and methods related to commonly used elliptic curves,
 * including their mathematical parameters such as 'a', 'b', 'p', 'n', 'gx', and 'gy'.
 */
enum EcCurve: string implements EcCurveEnumInterface
{
    case Secp256k1 = "secp256k1";
    case Secp256r1 = "secp256r1";
    case BrainpoolP256r1 = "brainpoolP256r1";

    /**
     * @return ScalarBitLength
     */
    public function scalarBitLength(): ScalarBitLength
    {
        return match($this) {
            self::BrainpoolP256r1,
            self::Secp256r1,
            self::Secp256k1 => ScalarBitLength::Bits256,
        };
    }

    /**
     * @return string
     */
    public function a(): string
    {
        return match ($this) {
            self::Secp256k1 => "00",
            self::Secp256r1 => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
            self::BrainpoolP256r1 => "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        };
    }

    /**
     * @return string
     */
    public function b(): string
    {
        return match ($this) {
            self::Secp256k1 => "07",
            self::Secp256r1 => "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            self::BrainpoolP256r1 => "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
        };
    }

    /**
     * @return string
     */
    public function p(): string
    {
        return match ($this) {
            self::Secp256k1 => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            self::Secp256r1 => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            self::BrainpoolP256r1 => "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        };
    }

    /**
     * @return string
     */
    public function n(): string
    {
        return match ($this) {
            self::Secp256k1 => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            self::Secp256r1 => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            self::BrainpoolP256r1 => "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        };
    }

    /**
     * @return string
     */
    public function gx(): string
    {
        return match ($this) {
            self::Secp256k1 => "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            self::Secp256r1 => "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            self::BrainpoolP256r1 => "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
        };
    }

    /**
     * @return string
     */
    public function gy(): string
    {
        return match ($this) {
            self::Secp256k1 => "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            self::Secp256r1 => "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
            self::BrainpoolP256r1 => "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
        };
    }
}