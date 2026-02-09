<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Codecs;

use Charcoal\Buffers\Support\ByteReader;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature;

/**
 * Utility class for encoding and decoding ECDSA signatures in DER format.
 */
final class EcdsaDerCodec
{
    /**
     * @param ScalarBitLength $scalarBits
     * @param ReadableBufferInterface|string $der
     * @return array{0: string, 1: string}
     */
    public static function decode(
        ScalarBitLength                $scalarBits,
        ReadableBufferInterface|string $der,
    ): array
    {
        $bytes = new ByteReader($der instanceof ReadableBufferInterface ? $der->bytes() : $der);
        if ($bytes->first(1) !== "\x30") {
            throw new \InvalidArgumentException("Invalid DER signature");
        }

        $signatureLength = $bytes->readUInt8();
        if ($bytes->size !== ($signatureLength + 2)) {
            throw new \LengthException("Invalid DER signature length");
        }

        if ($bytes->next(1) !== "\x02") {
            throw new \InvalidArgumentException("Expected R value to start with 0x02");
        }

        $rLength = $bytes->readUInt8();
        $r = $bytes->next($rLength);
        if ($bytes->next(1) !== "\x02") {
            throw new \InvalidArgumentException("Expected S value to start with 0x02");
        }

        $sLength = $bytes->readUInt8();
        $s = $bytes->next($sLength);
        if (!$bytes->isEnd()) {
            throw new \LengthException("Trailing bytes after DER signature");
        }

        if ($r === "\0" || $s === "\0") {
            throw new \InvalidArgumentException("Invalid ECDSA signature: zero scalar");
        }

        return [
            self::normalizeInteger($r, $scalarBits->byteLen(), "R"),
            self::normalizeInteger($s, $scalarBits->byteLen(), "S")
        ];
    }

    /**
     * @param EcdsaSignature $signature
     * @return string
     */
    public static function encode(EcdsaSignature $signature): string
    {
        $r = self::encodeInteger($signature->r->bytes());
        $s = self::encodeInteger($signature->s->bytes());
        $body = "\x02" . chr(strlen($r)) . $r . "\x02" . chr(strlen($s)) . $s;
        return "\x30" . chr(strlen($body)) . $body;
    }

    /**
     * @internal
     */
    private static function encodeInteger(string $x): string
    {
        $x = ltrim($x, "\0");
        if ($x === "") {
            $x = "\0";
        }

        if (ord($x[0]) >= 0x80) {
            $x = "\0" . $x;
        }

        return $x;
    }

    /**
     * @internal
     */
    private static function normalizeInteger(string $x, int $L, string $label): string
    {
        $n = strlen($x);
        if ($n < 1) {
            throw new \LengthException("Invalid DER: " . $label . " integer is empty");
        }

        if ((ord($x[0]) & 0x80) === 0x80) {
            throw new \InvalidArgumentException("Invalid DER: " . $label . " integer is negative");
        }

        if ($n > 1 && $x[0] === "\0") {
            if ((ord($x[1]) & 0x80) === 0) {
                throw new \InvalidArgumentException("Non-minimal DER: " . $label . " has unnecessary leading 0x00");
            }

            $x = substr($x, 1);
            $n--;
        }

        if ($n > 1 && $x[0] === "\0") {
            throw new \InvalidArgumentException("Non-minimal DER: " . $label . " has redundant leading zeros");
        }

        $x = ltrim($x, "\0");
        if ($x === "") {
            $x = "\0";
        }

        if (strlen($x) > $L) {
            throw new \LengthException("Invalid DER: " . $label . " integer too large");
        }

        if (strlen($x) < $L) {
            $x = str_pad($x, $L, "\0", STR_PAD_LEFT);
        }

        return $x;
    }
}