# kylix-ml-kem

Pure Rust implementation of **ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism), as specified in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

Part of the [Kylix](https://github.com/crane-valley/kylix) post-quantum cryptography library.

> [!WARNING]
> This library is experimental and has **NOT been audited**. Do not use in production.

## Features

- All three parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- SIMD acceleration: AVX2 (x86-64), NEON (AArch64) with runtime detection
- `no_std` compatible (requires `alloc`)
- Constant-time operations via `subtle`
- Automatic secret zeroization via `zeroize`
- IND-CCA2 security with implicit rejection
- NIST ACVP test vector compliance

## Usage

```toml
[dependencies]
kylix-ml-kem = "0.4"
```

### Key Exchange

```rust
use kylix_ml_kem::{MlKem768, Kem};

let mut rng = rand::rng();

// Key generation
let (dk, ek) = MlKem768::keygen(&mut rng).unwrap();

// Sender: encapsulate shared secret
let (ct, ss_sender) = MlKem768::encaps(&ek, &mut rng).unwrap();

// Receiver: decapsulate shared secret
let ss_receiver = MlKem768::decaps(&dk, &ct).unwrap();

assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
```

### Serialization

```rust
// Export keys as bytes
let ek_bytes = ek.as_bytes();
let dk_bytes = dk.as_bytes();

// Import keys from bytes
use kylix_ml_kem::ml_kem_768::{EncapsulationKey, DecapsulationKey};
let ek = EncapsulationKey::from_bytes(ek_bytes).unwrap();
let dk = DecapsulationKey::from_bytes(dk_bytes).unwrap();
```

## Parameter Sets

| Variant | Security Level | Public Key | Ciphertext | Shared Secret |
|---------|---------------|------------|------------|---------------|
| ML-KEM-512 | 1 (128-bit) | 800 B | 768 B | 32 B |
| ML-KEM-768 | 3 (192-bit) | 1,184 B | 1,088 B | 32 B |
| ML-KEM-1024 | 5 (256-bit) | 1,568 B | 1,568 B | 32 B |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | Yes | Standard library support |
| `simd` | Yes | SIMD optimizations (AVX2/NEON) |
| `ml-kem-512` | No | Enable ML-KEM-512 |
| `ml-kem-768` | Yes | Enable ML-KEM-768 |
| `ml-kem-1024` | No | Enable ML-KEM-1024 |

### no_std

```toml
kylix-ml-kem = { version = "0.4", default-features = false, features = ["ml-kem-768"] }
```

## License

MIT
