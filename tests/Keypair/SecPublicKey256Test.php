<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Tests\Keypair;

use Charcoal\Buffers\Buffer;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey256;
use PHPUnit\Framework\TestCase;

/**
 * Class SecPublicKey256Test
 * @package FurqanSiddiqui\Blockchain\Core\Tests\Keypair
 */
class SecPublicKey256Test extends TestCase
{
    private string $uncompressedHex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    private string $compressed2Hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    private string $compressed3Hex = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    public function testFromBytesUncompressed(): void
    {
        $bin = hex2bin($this->uncompressedHex);
        $pubKey = SecPublicKey256::fromBytes($bin);

        $this->assertSame("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", bin2hex($pubKey->x->bytes()));
        $this->assertNotNull($pubKey->y);
        $this->assertSame("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", bin2hex($pubKey->y->bytes()));
        $this->assertFalse($pubKey->parity);
        $this->assertFalse($pubKey->isCompressed());
    }

    public function testFromBytesCompressed02(): void
    {
        $bin = hex2bin($this->compressed2Hex);
        $pubKey = SecPublicKey256::fromBytes($bin);

        $this->assertSame("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", bin2hex($pubKey->x->bytes()));
        $this->assertNull($pubKey->y);
        $this->assertFalse($pubKey->parity);
        $this->assertTrue($pubKey->isCompressed());
    }

    public function testFromBytesCompressed03(): void
    {
        $bin = hex2bin($this->compressed3Hex);
        $pubKey = SecPublicKey256::fromBytes($bin);

        $this->assertSame("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", bin2hex($pubKey->x->bytes()));
        $this->assertNull($pubKey->y);
        $this->assertTrue($pubKey->parity);
        $this->assertTrue($pubKey->isCompressed());
    }

    public function testFromBytesWithBuffer(): void
    {
        $buffer = new Buffer(hex2bin($this->compressed2Hex));
        $pubKey = SecPublicKey256::fromBytes($buffer);

        $this->assertSame("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", bin2hex($pubKey->x->bytes()));
    }

    public function testFromBytesEmpty(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Empty public key");
        SecPublicKey256::fromBytes("");
    }

    public function testFromBytesInvalidPrefix(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid public key");
        SecPublicKey256::fromBytes(str_repeat("\xff", 33));
    }

    public function testFromBytesInvalidLengthUncompressed(): void
    {
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage("Expected 65 bytes for uncompressed public key, got 64 bytes");
        SecPublicKey256::fromBytes("\x04" . str_repeat("\x00", 63));
    }

    public function testFromBytesInvalidLengthCompressed(): void
    {
        $this->expectException(\LengthException::class);
        $this->expectExceptionMessage("Expected 33 bytes for compressed public key, got 32 bytes");
        SecPublicKey256::fromBytes("\x02" . str_repeat("\x00", 31));
    }
}
