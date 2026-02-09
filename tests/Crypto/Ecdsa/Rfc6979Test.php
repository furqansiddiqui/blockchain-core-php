<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Ecdsa;

use Charcoal\Buffers\Buffer;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa\Rfc6979;
use FurqanSiddiqui\Blockchain\Core\Enums\EcCurve;
use PHPUnit\Framework\TestCase;

/**
 * Class Rfc6979Test
 * @package FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Ecdsa
 */
class Rfc6979Test extends TestCase
{
    /**
     * NIST P-256 with SHA-256
     * @see https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
     */
    public function testNistP256Vectors(): void
    {
        $q = gmp_init(EcCurve::Secp256r1->n(), 16);
        $x = gmp_init("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);
        $msgHash = new Buffer(hex2bin("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"));
        $k = Rfc6979::generateK("sha256", $msgHash, $x, $q);
        $this->assertSame(
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
            bin2hex($k)
        );

        $msgHash2 = new Buffer(hex2bin("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
        $k2 = Rfc6979::generateK("sha256", $msgHash2, $x, $q);
        $this->assertSame(
            "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
            bin2hex($k2)
        );
    }

    /**
     * NIST P-256 with SHA-1
     * @see https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.5
     */
    public function testNistP256Sha1Vectors(): void
    {
        $q = gmp_init(EcCurve::Secp256r1->n(), 16);
        $x = gmp_init("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);
        $msgHash1 = new Buffer(hex2bin("8151325dcdbae9e0ff95f9f9658432dbedfdb209")); // "sample"
        $msgHash2 = new Buffer(hex2bin("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")); // "test"
        $k1 = Rfc6979::generateK("sha1", $msgHash1, $x, $q);
        $k2 = Rfc6979::generateK("sha1", $msgHash2, $x, $q);
        $this->assertSame(
            "882905f1227fd620fbf2abf21244f0ba83d0dc3a9103dbbee43a1fb858109db4",
            bin2hex($k1)
        );

        $this->assertSame(
            "8c9520267c55d6b980df741e56b4adee114d84fbfa2e62137954164028632a2e",
            bin2hex($k2)
        );
    }
}
