<?php
/*
 * Part of the "furqansiddiqui/blockchain-core-php" package.
 * @link https://github.com/furqansiddiqui/blockchain-core-php
 */

declare(strict_types=1);

namespace FurqanSiddiqui\Blockchain\Core\Crypto\Ecc;

use Charcoal\Buffers\Abstracts\FixedLengthImmutableBuffer;
use Charcoal\Contracts\Buffers\ReadableBufferInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\EcCurveEnumInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa\EcdsaInterface;
use FurqanSiddiqui\Blockchain\Core\Crypto\Ecdsa\Rfc6979;
use FurqanSiddiqui\Blockchain\Core\Keypair\SecPublicKey;
use FurqanSiddiqui\Blockchain\Core\Signatures\EcdsaSignature;

/**
 * Abstract class defining the implementation of a Weierstrass curve for elliptic curve cryptography (ECC).
 * It provides foundational operations such as key generation, signing, verification, and public key recovery.
 */
abstract readonly class AbstractWeierstrassCurve implements EcdsaInterface
{
    private int $scalarBitLength;
    private int $fieldByteLen;
    public \GMP $p;
    public \GMP $n;
    public \GMP $a;
    public \GMP $b;
    public EcPoint $G;

    abstract protected function createPublicKeyFromPoint(EcPoint $point): SecPublicKey;

    abstract protected function createSignatureInstance(\GMP $r, \GMP $s): EcdsaSignature;

    abstract protected function createCompressedPublicKey(\GMP $x, bool $yParity): SecPublicKey;

    /**
     * @param EcCurveEnumInterface $curveEnum
     * @param string $rfc6979Algorithm
     */
    public function __construct(
        public EcCurveEnumInterface $curveEnum,
        public string               $rfc6979Algorithm = "sha256"
    )
    {
        $this->p = gmp_init($this->curveEnum->p(), 16);
        $this->n = gmp_init($this->curveEnum->n(), 16);
        $this->a = gmp_init($this->curveEnum->a(), 16);
        $this->b = gmp_init($this->curveEnum->b(), 16);
        $this->G = new EcPoint($this, gmp_init($this->curveEnum->gx(), 16), gmp_init($this->curveEnum->gy(), 16));
        $this->scalarBitLength = $this->curveEnum->scalarBitLength()->value;
        $this->fieldByteLen = intdiv($this->scalarBitLength + 7, 8);
    }

    /**
     * @param FixedLengthImmutableBuffer $privateKey
     * @return void
     */
    public function validatePrivateKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): void
    {
        $this->ensurePrivateKey($privateKey);
    }

    /**
     * @param FixedLengthImmutableBuffer $privateKey
     * @return SecPublicKey
     */
    public function generatePublicKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): SecPublicKey
    {
        $k = $this->ensurePrivateKey($privateKey);
        return $this->createPublicKeyFromPoint($this->G->mul($k));
    }

    /**
     * @param FixedLengthImmutableBuffer $privateKey
     * @param ReadableBufferInterface $msgHash
     * @param ReadableBufferInterface|null $randomK
     * @return EcdsaSignature
     */
    public function sign(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey,
        ReadableBufferInterface    $msgHash,
        ?ReadableBufferInterface   $randomK = null
    ): EcdsaSignature
    {
        $pK = $this->ensurePrivateKey($privateKey);
        $m = $this->ensureMessageHash($msgHash);
        $kBytes = $randomK
            ? $randomK->bytes()
            : Rfc6979::generateK($this->rfc6979Algorithm, $msgHash, $pK, $this->n);

        // Validate nonce K
        $k = gmp_import($kBytes, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        if (gmp_cmp($k, 1) < 0) {
            throw new \UnderflowException("Nonce k is not positive");
        } elseif (gmp_cmp($k, $this->n) >= 0) {
            throw new \OverflowException("Nonce k is too large");
        }

        $kI = gmp_invert($k, $this->n);
        if ($kI === false) {
            throw new \RuntimeException("Nonce k has no inverse mod n");
        }

        // Signature point R
        $r = gmp_mod($this->G->mul($k)->x, $this->n);
        if (gmp_cmp($r, 0) === 0) {
            throw new \RuntimeException("Signature point R is zero");
        }

        // Signature point S
        $s = gmp_mod(gmp_mul($kI, gmp_add($m, gmp_mul($pK, $r))), $this->n);
        if (gmp_cmp($s, 0) === 0) {
            throw new \RuntimeException("Signature point S is zero");
        }

        // BIP 62, make sure we use the low-s value
        if (gmp_cmp($s, gmp_div_q($this->n, 2)) > 0) {
            $s = gmp_sub($this->n, $s);
        }

        return $this->createSignatureInstance($r, $s);
    }

    /**
     * @param SecPublicKey $publicKey
     * @param EcdsaSignature $signature
     * @param ReadableBufferInterface $msgHash
     * @return bool
     */
    public function verify(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): bool
    {
        try {
            [$r, $s] = $this->signatureToGmp($signature);
        } catch (\Throwable) {
            return false;
        }

        $m = $this->ensureMessageHash($msgHash);
        $publicKey = $this->publicKeyToPoint($this->expandPublicKey($publicKey));
        if (!$publicKey->validate()) {
            return false;
        }

        $sI = gmp_invert($s, $this->n);
        if ($sI === false) {
            return false;
        }

        $u1 = gmp_mod(gmp_mul($m, $sI), $this->n);
        $u2 = gmp_mod(gmp_mul($r, $sI), $this->n);

        try {
            $P = $this->G->mul($u1)->add($publicKey->mul($u2));
        } catch (\Throwable) {
            return false;
        }

        $x = gmp_mod($P->x, $this->n);
        return gmp_cmp($x, $r) === 0;
    }

    /**
     * @param SecPublicKey $publicKey
     * @return SecPublicKey
     */
    public function expandPublicKey(
        SecPublicKey $publicKey
    ): SecPublicKey
    {
        if (!$publicKey->isCompressed()) {
            return $publicKey;
        }

        if ($publicKey->x->length() !== $this->fieldByteLen) {
            throw new \InvalidArgumentException("Invalid public key X length");
        }

        $x = gmp_import($publicKey->x->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        $x3 = gmp_powm($x, 3, $this->p);
        $ax = gmp_mod(gmp_mul($this->a, $x), $this->p);
        $y = gmp_mod(gmp_add(gmp_add($x3, $ax), $this->b), $this->p);
        $y = EcMath::sqrt($y, $this->p);
        if (!$y) {
            throw new \RuntimeException("Could not find Y coordinate for public key");
        }

        $yParity = $publicKey->parity ? 1 : 0;
        if (gmp_intval(gmp_mod($y[0], 2)) === $yParity) {
            return $this->createPublicKeyFromPoint(new EcPoint($this, $x, $y[0]));
        } elseif (gmp_intval(gmp_mod($y[1], 2)) === $yParity) {
            return $this->createPublicKeyFromPoint(new EcPoint($this, $x, $y[1]));
        }

        throw new \RuntimeException("Could not find Y coordinate for public key");
    }

    /**
     * @param EcdsaSignature $signature
     * @param ReadableBufferInterface $msgHash
     * @param int|null $recoveryId
     * @return SecPublicKey
     */
    public function recoverPublicKey(
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash,
        ?int                    $recoveryId = null
    ): SecPublicKey
    {
        [$r, $s] = $this->signatureToGmp($signature);
        $rI = gmp_invert($r, $this->n);
        if ($rI === false) {
            throw new \RuntimeException("r has no inverse");
        }

        $m = $this->ensureMessageHash($msgHash);
        $recoveryId = $recoveryId ?? $signature->recoveryId;
        if (!is_int($recoveryId) || $recoveryId < 0 || $recoveryId > 3) {
            throw new \RuntimeException("Invalid recovery ID: " . $recoveryId);
        }

        // Step 1.1
        $recoveryId = gmp_init($recoveryId, 10);
        $x = gmp_add($r, gmp_mul($this->n, gmp_div_q($recoveryId, 2)));
        if (gmp_cmp($x, $this->p) >= 0) {
            throw new \RuntimeException("Invalid recovery ID (x >= p)");
        }

        // Step 1.3
        $pubKey = $this->expandPublicKey($this->createCompressedPublicKey($x, gmp_intval(gmp_mod($recoveryId, 2)) === 1));
        $y = gmp_import($pubKey->y->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);

        // Step 1.6.1
        $R = new EcPoint($this, $x, $y);
        if (!$R->validate()) {
            throw new \RuntimeException("Invalid public key point R");
        }

        $sR = $R->mul($s);
        $zG = $this->G->mul($m);
        $negZG = new EcPoint($this, $zG->x, gmp_mod(gmp_neg($zG->y), $this->p));
        $Q = $sR->add($negZG)->mul($rI);
        $publicKey = $this->createPublicKeyFromPoint($Q);
        if ($this->verify($publicKey, $signature, $msgHash)) {
            return $publicKey;
        }

        throw new \RuntimeException("Could not recover public key from signature (invalid signature)");
    }

    /**
     * @param SecPublicKey $publicKey
     * @param EcdsaSignature $signature
     * @param ReadableBufferInterface $msgHash
     * @return int
     */
    public function findRecoveryId(
        SecPublicKey            $publicKey,
        EcdsaSignature          $signature,
        ReadableBufferInterface $msgHash
    ): int
    {
        $publicKey = $this->expandPublicKey($publicKey);
        for ($v = 0; $v < 4; $v++) {
            try {
                $recovered = $this->recoverPublicKey($signature, $msgHash, $v);
                if ($recovered->parity === $publicKey->parity) {
                    if ($recovered->x->equals($publicKey->x)) {
                        if ($recovered->y->equals($publicKey->y)) {
                            return $v;
                        }
                    }
                }
            } catch (\Throwable) {
                // ignore and continue
            }
        }

        throw new \RuntimeException("Could not find recovery ID for signature");
    }

    /**
     * @param EcdsaSignature $signature
     * @return array{0:\GMP, 1:\GMP}
     */
    private function signatureToGmp(EcdsaSignature $signature): array
    {
        $r = gmp_import($signature->r->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, $this->n) >= 0) {
            throw new \InvalidArgumentException("Invalid signature R value");
        }

        $s = gmp_import($signature->s->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, $this->n) >= 0) {
            throw new \InvalidArgumentException("Invalid signature S value");
        }

        return [$r, $s];
    }

    /**
     * @param SecPublicKey $publicKey
     * @return EcPoint
     */
    private function publicKeyToPoint(SecPublicKey $publicKey): EcPoint
    {
        if ($publicKey->isCompressed()) {
            throw new \RuntimeException("Compressed public keys are not supported");
        }

        return new EcPoint(
            $this,
            gmp_import($publicKey->x->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST),
            gmp_import($publicKey->y->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST)
        );
    }

    /**
     * @param ReadableBufferInterface $msgHash
     * @return \GMP
     */
    private function ensureMessageHash(ReadableBufferInterface $msgHash): \GMP
    {
        $z = gmp_import($msgHash->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        $hashBits = $msgHash->length() * 8;
        if ($hashBits > $this->scalarBitLength) {
            $z = gmp_div_q($z, gmp_pow(2, $hashBits - $this->scalarBitLength));
        }

        return $z;
    }

    /**
     * @param FixedLengthImmutableBuffer $privateKey
     * @return \GMP
     */
    private function ensurePrivateKey(
        #[\SensitiveParameter]
        FixedLengthImmutableBuffer $privateKey
    ): \GMP
    {
        if (($privateKey->length() * 8) !== $this->scalarBitLength) {
            throw new \InvalidArgumentException("Private key length does not match curve scalar bit length: " .
                $this->scalarBitLength);
        }

        $k = gmp_import($privateKey->bytes(), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST);
        if (gmp_cmp($k, 1) < 0) {
            throw new \UnderflowException("Private key integer value is not positive");
        } elseif (gmp_cmp($k, $this->n) >= 0) {
            throw new \OverflowException("Private key integer value is too large");
        }

        return $k;
    }
}