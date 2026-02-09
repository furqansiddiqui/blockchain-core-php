# Blockchain Core PHP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight PHP library providing cryptographic primitives and elliptic curve abstractions specifically tailored for blockchain development.

## Features

- **Elliptic Curves Support**: 
  - `secp256k1` (Bitcoin, Ethereum)
  - `secp256r1` (NIST P-256)
  - `brainpoolP256r1`
- **ECDSA (Elliptic Curve Digital Signature Algorithm)**:
  - High-performance pure-PHP implementation using `ext-gmp`.
  - Deterministic nonce generation via **RFC 6979**.
  - Canonical signature enforcement (**BIP 66**).
  - Public key recovery from signatures.
  - Support for compressed and uncompressed public keys.
- **EdDSA Support**:
  - Abstractions for Edwards-curve Digital Signature Algorithm (e.g., Ed25519).
- **Security Focused**:
  - Uses PHP 8.3 `#[\SensitiveParameter]` attribute to protect private keys in backtraces.
  - Implements Low-S normalization for ECDSA signatures.

## Requirements

- PHP 8.3 or higher.
- `ext-gmp` extension.

## Installation

You can install the package via composer:

```bash
composer require furqansiddiqui/blockchain-core-php
```

## Usage

### Secp256k1 Key Generation and Signing

```php
use FurqanSiddiqui\Blockchain\Core\Crypto\Curves\Secp256k1;
use Charcoal\Buffers\Types\Bytes32;

$secp256k1 = new Secp256k1();

// 1. Generate a public key from a private key
$privateKey = new Bytes32(hex2bin("...32_byte_hex_private_key..."));
$publicKey = $secp256k1->generatePublicKey($privateKey);

echo "Public Key (X): " . bin2hex($publicKey->x->bytes()) . PHP_EOL;
echo "Public Key (Y): " . bin2hex($publicKey->y->bytes()) . PHP_EOL;

// 2. Sign a message hash (must be 32 bytes for secp256k1)
$msgHash = new Bytes32(hash("sha256", "Hello Blockchain", true));
$signature = $secp256k1->sign($privateKey, $msgHash);

echo "Signature R: " . bin2hex($signature->r->bytes()) . PHP_EOL;
echo "Signature S: " . bin2hex($signature->s->bytes()) . PHP_EOL;

// 3. Verify the signature
$isValid = $secp256k1->verify($publicKey, $signature, $msgHash);
var_dump($isValid); // bool(true)
```

### Working with DER Signatures (BIP 66)

```php
use FurqanSiddiqui\Blockchain\Core\Codecs\EcdsaDerCodec;

// Encode signature to DER
$der = $signature->toDER();
echo "DER: " . bin2hex($der) . PHP_EOL;

// Decode DER signature
// (Requires specifying expected scalar bit length)
use FurqanSiddiqui\Blockchain\Core\Enums\ScalarBitLength;
[$r, $s] = EcdsaDerCodec::decode(ScalarBitLength::Bits256, $der);
```

## Testing

The library is thoroughly tested with vectors from `libsecp256k1`, RFC 6979, and standard NIST vectors.

To run the tests:

```bash
php phpunit.phar
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.