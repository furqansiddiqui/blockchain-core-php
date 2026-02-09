<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa;

use Charcoal\Contracts\Buffers\ReadableBufferInterface;

/**
 * Implements the deterministic nonce generation as specified by RFC 6979.
 */
final readonly class Rfc6979
{
    /** @var array<string,int> */
    private const array HASH_ALGO_BITS = [
        "sha1" => 160,
        "sha256" => 256,
        "sha512" => 512,
    ];

    /**
     * RFC6979 deterministic nonce generation for ECDSA
     */
    public static function generateK(
        string                       $algo,
        ReadableBufferInterface      $msgHash,
        \GMP|ReadableBufferInterface $privateKey,
        \GMP                         $order
    ): string
    {
        $algo = strtolower($algo);
        if (!isset(self::HASH_ALGO_BITS[$algo])) {
            throw new \InvalidArgumentException("Invalid/unsupported hash-hmac algorithm");
        }

        $hLenBits = self::HASH_ALGO_BITS[$algo];
        $hLenBytes = $hLenBits >> 3;
        $h1 = $msgHash->bytes();
        if (strlen($h1) !== $hLenBytes) {
            throw new \InvalidArgumentException("Invalid message digest length");
        }

        $q = $order;
        if (gmp_cmp($q, 0) <= 0) {
            throw new \InvalidArgumentException("Invalid ECDSA curve order");
        }

        $x = $privateKey instanceof ReadableBufferInterface
            ? gmp_import($privateKey->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)
            : $privateKey;

        if (gmp_cmp($x, 1) < 0 || gmp_cmp($x, gmp_sub($q, 1)) > 0) {
            throw new \InvalidArgumentException("Invalid private key scalar");
        }

        $qLen = strlen(gmp_strval($q, 2));
        $rLen = ($qLen + 7) >> 3;

        // Step A
        $bx = self::int2octets($x, $rLen) . self::bits2octets($h1, $q, $qLen, $rLen);

        // Step B
        $v = str_repeat("\x01", $hLenBytes);

        // Step C
        $k = str_repeat("\x00", $hLenBytes);

        // Step D
        $k = hash_hmac($algo, $v . "\x00" . $bx, $k, true);

        // Step E
        $v = hash_hmac($algo, $v, $k, true);

        // Step F
        $k = hash_hmac($algo, $v . "\x01" . $bx, $k, true);

        // Step G
        $v = hash_hmac($algo, $v, $k, true);

        // Step H+
        for ($attempt = 0; $attempt < 10000; $attempt++) {
            $t = "";
            while (strlen($t) < $rLen) {
                $v = hash_hmac($algo, $v, $k, true);
                $t .= $v;
            }

            $candidate = self::bits2int($t, $qLen);
            if (gmp_cmp($candidate, 1) >= 0 && gmp_cmp($candidate, $q) < 0) {
                return self::int2octets($candidate, $rLen);
            }

            $k = hash_hmac($algo, $v . "\x00", $k, true);
            $v = hash_hmac($algo, $v, $k, true);
        }

        throw new \RuntimeException("Failed to generate RFC6979 randomK value");
    }

    /**
     * @param \GMP $x
     * @param int $rLen
     * @return string
     */
    private static function int2octets(\GMP $x, int $rLen): string
    {
        if (gmp_cmp($x, 0) < 0) {
            throw new \InvalidArgumentException("Negative integer not allowed");
        }

        $bin = gmp_export($x, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST) ?: "";
        if (strlen($bin) > $rLen) {
            $bin = substr($bin, -$rLen);
        }

        return str_pad($bin, $rLen, "\x00", STR_PAD_LEFT);
    }

    /**
     * @param string $in
     * @param int $qLen
     * @return \GMP
     */
    private static function bits2int(string $in, int $qLen): \GMP
    {
        if ($in === "") {
            return gmp_init("0", 10);
        }

        $v = gmp_init(bin2hex($in), 16);
        $vLen = strlen($in) * 8;
        if ($vLen > $qLen) {
            $v = gmp_div_q($v, gmp_pow(2, $vLen - $qLen));
        }

        return $v;
    }

    /**
     * @param string $h1
     * @param \GMP $q
     * @param int $qLen
     * @param int $rLen
     * @return string
     */
    private static function bits2octets(string $h1, \GMP $q, int $qLen, int $rLen): string
    {
        $z1 = self::bits2int($h1, $qLen);
        if (gmp_cmp($z1, $q) >= 0) {
            $z1 = gmp_sub($z1, $q);
        }

        return self::int2octets($z1, $rLen);
    }
}

