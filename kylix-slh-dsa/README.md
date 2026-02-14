# kylix-slh-dsa

Pure Rust implementation of **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm), as specified in [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

Part of the [Kylix](https://github.com/crane-valley/kylix) post-quantum cryptography library.

> [!WARNING]
> This library is experimental and has **NOT been audited**. Do not use in production.

## Features

- All 12 parameter sets: SHAKE and SHA2 variants at 128/192/256-bit security, fast and small
- Optional parallel signing via `rayon`
- `no_std` compatible (requires `alloc`)
- Constant-time operations via `subtle`
- Automatic secret zeroization via `zeroize`
- NIST ACVP test vector compliance

## Usage

```toml
[dependencies]
kylix-slh-dsa = "0.4"
rand = "0.9"
```

### Sign and Verify

```rust
use kylix_slh_dsa::{SlhDsaShake128f, Signer};

let mut rng = rand::rng();

// Key generation
let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

// Sign a message
let message = b"Hello, post-quantum world!";
let signature = SlhDsaShake128f::sign(&sk, message).unwrap();

// Verify the signature
assert!(SlhDsaShake128f::verify(&pk, message, &signature).is_ok());
```

### Parallel Signing

Enable the `parallel` feature for faster signing via multi-threaded FORS computation:

```toml
kylix-slh-dsa = { version = "0.4", features = ["parallel"] }
```

### Serialization

```rust
let sk_bytes = sk.as_bytes();
let pk_bytes = pk.as_bytes();
let sig_bytes = signature.as_bytes();

use kylix_slh_dsa::slh_dsa_shake_128f::{SigningKey, VerificationKey, Signature};
let sk = SigningKey::from_bytes(sk_bytes).unwrap();
let pk = VerificationKey::from_bytes(pk_bytes).unwrap();
let sig = Signature::from_bytes(sig_bytes).unwrap();
```

## Parameter Sets

### SHAKE-based (default)

| Variant | Security | PK | SK | Signature | Speed |
|---------|----------|-----|-----|-----------|-------|
| SHAKE-128s | Level 1 | 32 B | 64 B | 7,856 B | Slow |
| SHAKE-128f | Level 1 | 32 B | 64 B | 17,088 B | Fast |
| SHAKE-192s | Level 3 | 48 B | 96 B | 16,224 B | Slow |
| SHAKE-192f | Level 3 | 48 B | 96 B | 35,664 B | Fast |
| SHAKE-256s | Level 5 | 64 B | 128 B | 29,792 B | Slow |
| SHAKE-256f | Level 5 | 64 B | 128 B | 49,856 B | Fast |

### SHA2-based (optional)

Same sizes as SHAKE variants. Enable with `slh-dsa-sha2-{128s,128f,...}` features.

**Trade-off**: "fast" variants have larger signatures but significantly faster signing; "small" variants minimize signature size at ~10x slower signing.

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | Yes | Standard library support |
| `slh-dsa-shake-128f` | Yes | Default variant |
| `slh-dsa-shake-{128s,192s,192f,256s,256f}` | No | Other SHAKE variants |
| `slh-dsa-sha2-{128s,128f,192s,192f,256s,256f}` | No | SHA2-based variants |
| `parallel` | No | Multi-threaded signing (requires `std`) |

### no_std

```toml
kylix-slh-dsa = { version = "0.4", default-features = false, features = ["slh-dsa-shake-128f"] }
```

## License

MIT
