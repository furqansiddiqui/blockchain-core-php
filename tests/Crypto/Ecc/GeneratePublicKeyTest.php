<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Ecc;

use Charcoal\Buffers\Types\Bytes32;
use FurqanSiddiqui\Blockchain\Core\Crypto\Curves\EcCurve256;
use FurqanSiddiqui\Blockchain\Core\Enums\EcCurve;
use PHPUnit\Framework\TestCase;

/**
 * Class GeneratePublicKeyTest
 * @package FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Ecc
 */
class GeneratePublicKeyTest extends TestCase
{
    /**
     * @return void
     */
    public function testSecp256k1(): void
    {
        // Vector from: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        $d = new Bytes32(hex2bin("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"));
        $expectedX = "50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352";
        $expectedY = "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";

        $curve = new EcCurve256(EcCurve::Secp256k1);
        $pubKey = $curve->generatePublicKey($d);
        $this->assertSame(strtolower($expectedX), bin2hex($pubKey->x->bytes()));
        $this->assertSame(strtolower($expectedY), bin2hex($pubKey->y->bytes()));
    }

    /**
     * @return void
     */
    public function testSecp256r1(): void
    {
        // Vector from: https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_test.json
        // Or standard NIST vectors.
        // d = 1
        $d = new Bytes32(hex2bin("0000000000000000000000000000000000000000000000000000000000000001"));
        $expectedX = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        $expectedY = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

        $curve = new EcCurve256(EcCurve::Secp256r1);
        $pubKey = $curve->generatePublicKey($d);
        $this->assertSame(strtolower($expectedX), bin2hex($pubKey->x->bytes()));
        $this->assertSame(strtolower($expectedY), bin2hex($pubKey->y->bytes()));
    }

    /**
     * @return void
     */
    public function testBrainpoolP256r1(): void
    {
        // Vector from: RFC 5639, Section 10
        // d = 1
        $d = new Bytes32(hex2bin("0000000000000000000000000000000000000000000000000000000000000001"));
        $expectedX = "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262";
        $expectedY = "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997";

        $curve = new EcCurve256(EcCurve::BrainpoolP256r1);
        $pubKey = $curve->generatePublicKey($d);
        $this->assertSame(strtolower($expectedX), bin2hex($pubKey->x->bytes()));
        $this->assertSame(strtolower($expectedY), bin2hex($pubKey->y->bytes()));
    }
}