<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Tests\Codecs;

use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature256;
use PHPUnit\Framework\TestCase;
use FurqanSiddiqui\Blockchain\Core\Codecs\EcdsaDerCodec;
use Charcoal\Buffers\Types\Bytes32;

/**
 * Class EcdsaDerCodecTest
 * @package FurqanSiddiqui\Blockchain\Core\Tests\Codecs
 */
class EcdsaDerCodecTest extends TestCase
{
    public function testEncodeBasic(): void
    {
        $r = str_repeat("\x01", 32);
        $s = str_repeat("\x02", 32);
        $sig = new EcdsaSignature256(new Bytes32($r), new Bytes32($s));
        $der = EcdsaDerCodec::encode($sig);
        $expected = "\x30\x44\x02\x20" . $r . "\x02\x20" . $s;
        $this->assertSame(bin2hex($expected), bin2hex($der));
    }

    public function testEncodeWithHighBit(): void
    {
        $r = "\x80" . str_repeat("\x00", 31);
        $s = "\xff" . str_repeat("\x00", 31);
        $sig = new EcdsaSignature256(new Bytes32($r), new Bytes32($s));
        $der = EcdsaDerCodec::encode($sig);
        $expected = "\x30\x46\x02\x21\x00" . $r . "\x02\x21\x00" . $s;
        $this->assertSame(bin2hex($expected), bin2hex($der));
    }

    public function testDecodeBasic(): void
    {
        $r = str_repeat("\x01", 32);
        $s = str_repeat("\x02", 32);
        $der = "\x30\x44\x02\x20" . $r . "\x02\x20" . $s;

        [$decodedR, $decodedS] = EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
        $this->assertSame(bin2hex($r), bin2hex($decodedR));
        $this->assertSame(bin2hex($s), bin2hex($decodedS));
    }

    public function testDecodeWithPadding(): void
    {
        // R is 1 byte, S is 1 byte
        $r = "\x01";
        $s = "\x7f";
        $der = "\x30\x06\x02\x01\x01\x02\x01\x7f";
        [$decodedR, $decodedS] = EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
        $this->assertSame(bin2hex(str_pad($r, 32, "\0", STR_PAD_LEFT)), bin2hex($decodedR));
        $this->assertSame(bin2hex(str_pad($s, 32, "\0", STR_PAD_LEFT)), bin2hex($decodedS));
    }

    public function testDecodeBIP66InvalidTag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x31\x06\x02\x01\x01\x02\x01\x01");
    }

    public function testDecodeBIP66InvalidLength(): void
    {
        $this->expectException(\LengthException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x07\x02\x01\x01\x02\x01\x01");
    }

    public function testDecodeBIP66InvalidRTag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x06\x03\x01\x01\x02\x01\x01");
    }

    public function testDecodeBIP66InvalidSTag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x06\x02\x01\x01\x03\x01\x01");
    }

    public function testDecodeBIP66NegativeR(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x06\x02\x01\x80\x02\x01\x01");
    }

    public function testDecodeBIP66NonMinimalR(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x07\x02\x02\x00\x01\x02\x01\x01");
    }

    public function testDecodeBIP66RedundantZerosR(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x08\x02\x03\x00\x00\x80\x02\x01\x01");
    }

    public function testDecodeBIP66TrailingBytes(): void
    {
        $this->expectException(\LengthException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, "\x30\x06\x02\x01\x01\x02\x01\x01\xff");
    }

    public function testDecodeTooLargeR(): void
    {
        $this->expectException(\LengthException::class);
        $r = str_repeat("\x01", 33);
        $der = "\x30\x26\x02\x21" . $r . "\x02\x01\x01";
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
    }

    public function testDecodeInvalidInternalLength(): void
    {
        $this->expectException(\Exception::class);
        $der = "\x30\x06\x02\x0A\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
    }

    public function testDecodeValueEqualsOrderN(): void
    {
        $nHex = "fffffffffffffffffffffffffffffffebaaedceaf48a03bbfd25e8cd0364141";
        $nBin = hex2bin($nHex);
        $r = str_repeat("\x01", 32);
        $s = "\x00" . $nBin;

        $der = "\x30\x47\x02\x20" . $r . "\x02\x21" . $s;
        $this->expectException(\LengthException::class);
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
    }

    public function testDecodeZeroValues(): void
    {
        $this->expectException(\Exception::class);
        $der = "\x30\x06\x02\x01\x00\x02\x01\x01";
        EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
    }
}
