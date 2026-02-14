# kylix-ml-dsa

Pure Rust implementation of **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm), as specified in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

Part of the [Kylix](https://github.com/crane-valley/kylix) post-quantum cryptography library.

> [!WARNING]
> This library is experimental and has **NOT been audited**. Do not use in production.

## Features

- All three parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
- SIMD acceleration: AVX2 (x86-64), NEON (AArch64), WASM-SIMD128
- Expanded verification key for 2-3x faster repeated verification
- `no_std` compatible (requires `alloc`)
- Constant-time operations via `subtle`
- Automatic secret zeroization via `zeroize`
- NIST ACVP test vector compliance

## Usage

```toml
[dependencies]
kylix-ml-dsa = "0.4"
```

### Sign and Verify

```rust
use kylix_ml_dsa::{MlDsa65, Signer};

let mut rng = rand::rng();

// Key generation
let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = MlDsa65::sign(&sk, message).unwrap();

// Verify the signature
assert!(MlDsa65::verify(&pk, message, &signature).is_ok());
```

### Expanded Verification (Batch Optimization)

Pre-expand the verification key for faster repeated verification with the same public key:

```rust
// One-time expansion (~68 µs)
let expanded = pk.expand().unwrap();

// Fast verification (~38 µs vs ~101 µs regular)
for (msg, sig) in messages_and_signatures {
    MlDsa65::verify_expanded(&expanded, msg, &sig).unwrap();
}
```

Break-even at 2 verifications with the same key.

### Serialization

```rust
let sk_bytes = sk.as_bytes();
let pk_bytes = pk.as_bytes();
let sig_bytes = signature.as_bytes();

use kylix_ml_dsa::dsa65::{SigningKey, VerificationKey, Signature};
let sk = SigningKey::from_bytes(sk_bytes).unwrap();
let pk = VerificationKey::from_bytes(pk_bytes).unwrap();
let sig = Signature::from_bytes(sig_bytes).unwrap();
```

## Parameter Sets

| Variant | Security Level | Signing Key | Verification Key | Signature |
|---------|---------------|-------------|-----------------|-----------|
| ML-DSA-44 | 2 (128-bit) | 2,560 B | 1,312 B | 2,420 B |
| ML-DSA-65 | 3 (192-bit) | 4,032 B | 1,952 B | 3,309 B |
| ML-DSA-87 | 5 (256-bit) | 4,896 B | 2,592 B | 4,627 B |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | Yes | Standard library support |
| `simd` | Yes | SIMD optimizations (AVX2/NEON/WASM-SIMD128) |
| `ml-dsa-44` | No | Enable ML-DSA-44 |
| `ml-dsa-65` | Yes | Enable ML-DSA-65 |
| `ml-dsa-87` | No | Enable ML-DSA-87 |

### no_std

```toml
kylix-ml-dsa = { version = "0.4", default-features = false, features = ["ml-dsa-65"] }
```

## License

MIT
