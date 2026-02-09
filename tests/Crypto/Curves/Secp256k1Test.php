<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Curves;

use Charcoal\Buffers\Types\Bytes32;
use FurqanSiddiqui\Blockchain\Core\Crypto\Curves\Secp256k1;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa\Rfc6979;
use FurqanSiddiqui\Blockchain\Core\Enums\CompactSignature;
use FurqanSiddiqui\Blockchain\Core\Enums\EcCurve;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature256;
use PHPUnit\Framework\TestCase;

/**
 * Class Secp256k1Test
 * @package FurqanSiddiqui\Blockchain\Core\Tests\Crypto\Curves
 */
class Secp256k1Test extends TestCase
{
    /**
     * @return void
     */
    public function testPublicKeyGeneration(): void
    {
        $secp256k1 = new Secp256k1();

        // Canonical secp256k1 generator test (d = 1)
        $d = new Bytes32(hex2bin("0000000000000000000000000000000000000000000000000000000000000001"));

        $pubKey = $secp256k1->generatePublicKey($d);

        $this->assertSame(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            bin2hex($pubKey->x->bytes())
        );

        $this->assertSame(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            bin2hex($pubKey->y->bytes())
        );
    }


    /**
     * @return void
     */
    public function testEcdsaSigningAndVerification(): void
    {
        $secp256k1 = new Secp256k1();

        $d = new Bytes32(hex2bin(str_pad("09", 64, "0", STR_PAD_LEFT)));
        $msgHash = new Bytes32(hex2bin(
            "af2b1e42857461972f588a83d7c3583c483a93f18e9f4e242400e95738806295"
        ));

        $sig1 = $secp256k1->sign($d, $msgHash);
        $sig2 = $secp256k1->sign($d, $msgHash);

        // Deterministic signature (RFC6979)
        $this->assertSame(
            $sig1->toCompact(CompactSignature::RS),
            $sig2->toCompact(CompactSignature::RS),
            "Signature not deterministic"
        );

        $pubKey = $secp256k1->generatePublicKey($d);

        $this->assertTrue(
            $secp256k1->verify($pubKey, $sig1, $msgHash),
            "Verification failed"
        );
    }


    /**
     * @return void
     */
    public function testInvalidSignatureVerification(): void
    {
        $secp256k1 = new Secp256k1();

        $d = new Bytes32(hex2bin(str_pad("01", 64, "0", STR_PAD_LEFT)));
        $msgHash = new Bytes32(hex2bin(
            "af2b1e42857461972f588a83d7c3583c483a93f18e9f4e242400e95738806295"
        ));

        $pubKey = $secp256k1->generatePublicKey($d);
        $signature = $secp256k1->sign($d, $msgHash);

        // Mutate r (guaranteed invalid)
        $r = $signature->r->bytes();
        $r[0] = $r[0] ^ "\x01";

        $invalidSignature = new EcdsaSignature256(
            new Bytes32($r),
            $signature->s
        );

        $this->assertFalse(
            $secp256k1->verify($pubKey, $invalidSignature, $msgHash),
            "Invalid signature verified as true"
        );
    }

    /**
     * @return void
     */
    public function testRfc6979Vectors(): void
    {
        $secp256k1 = new Secp256k1();
        $order = gmp_init(EcCurve::Secp256k1->n(), 16);

        // Test Vectors for RFC 6979 ECDSA, secp256k1, SHA-256
        // (private key, message, expected k, expected signature)
        $vectors = [
            [
                "d" => "0000000000000000000000000000000000000000000000000000000000000001",
                "msg" => "Satoshi Nakamoto",
                "k" => "8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15",
                "sig" => "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8dbbd3162d46e9f9bef7feb87c16dc13b4f6568a87f4e83f728e2443ba586675c"
            ],
            [
                "d" => "0000000000000000000000000000000000000000000000000000000000000001",
                "msg" => "All those moments will be lost in time, like tears in rain. Time to die...",
                "k" => "38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3",
                "sig" => "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6bab8019bbd8b6924cc4099fe625340ffb1eaac34bf4477daa39d0835429094520"
            ],
            [
                "d" => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
                "msg" => "Satoshi Nakamoto",
                "k" => "33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90",
                "sig" => "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d094c632f14e4379fc1ea610a3df5a375152549736425ee17cebe10abbc2a2826c"
            ],
            [
                "d" => "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
                "msg" => "Alan Turing",
                "k" => "525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1",
                "sig" => "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15ca72033e1ff5ca1ea8d0c99001cb45f0272d3be7525d3049c0d9e98dc7582b857"
            ]
        ];

        foreach ($vectors as $vector) {
            $d = new Bytes32(hex2bin($vector["d"]));
            $msgHash = new Bytes32(hash("sha256", $vector["msg"], true));

            // Verify k
            $k = Rfc6979::generateK("sha256", $msgHash, $d, $order);
            $this->assertSame(strtolower($vector["k"]), bin2hex($k), "k mismatch for " . $vector["msg"]);

            // Verify Signature
            $signature = $secp256k1->sign($d, $msgHash);
            $expectedR = substr($vector["sig"], 0, 64);
            $expectedS = gmp_init(substr($vector["sig"], 64, 64), 16);

            // The library enforces Low-S (BIP 62)
            if (gmp_cmp($expectedS, gmp_div_q($order, 2)) > 0) {
                $expectedS = gmp_sub($order, $expectedS);
            }

            $expectedSHex = str_pad(gmp_strval($expectedS, 16), 64, "0", STR_PAD_LEFT);

            $this->assertSame(strtolower($expectedR), bin2hex($signature->r->bytes()), "R mismatch for " . $vector["msg"]);
            $this->assertSame(strtolower($expectedSHex), bin2hex($signature->s->bytes()), "S mismatch for " . $vector["msg"]);

            // Verify
            $pubKey = $secp256k1->generatePublicKey($d);
            $this->assertTrue($secp256k1->verify($pubKey, $signature, $msgHash), "Verification failed for " . $vector["msg"]);
        }
    }
}
