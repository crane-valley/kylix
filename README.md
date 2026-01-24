# Kylix

[![CI](https://github.com/crane-valley/kylix/actions/workflows/ci.yml/badge.svg)](https://github.com/crane-valley/kylix/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/kylix-pqc.svg)](https://crates.io/crates/kylix-pqc)
[![Documentation](https://docs.rs/kylix-pqc/badge.svg)](https://docs.rs/kylix-pqc)
[![Website](https://img.shields.io/badge/Website-kylix--pqc.dev-blue)](https://kylix-pqc.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.75-blue.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

A post-quantum cryptography library implementing NIST FIPS standards in pure Rust.

## Features

- **ML-KEM** (FIPS 203): Module-Lattice-Based Key Encapsulation Mechanism
  - ML-KEM-512 (Security Level 1)
  - ML-KEM-768 (Security Level 3)
  - ML-KEM-1024 (Security Level 5)
- **ML-DSA** (FIPS 204): Module-Lattice-Based Digital Signature Algorithm
  - ML-DSA-44 (Security Level 2)
  - ML-DSA-65 (Security Level 3)
  - ML-DSA-87 (Security Level 5)
- `no_std` compatible for embedded systems
- Constant-time implementations to prevent timing attacks
- Secure memory handling with automatic zeroization
- Comprehensive test coverage including NIST ACVP vectors

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kylix-pqc = "0.3"
```

## Usage

### ML-KEM (Key Encapsulation)

```rust
use kylix_pqc::ml_kem::{MlKem768, Kem};
use rand::rngs::OsRng;

fn main() -> kylix_pqc::Result<()> {
    // Generate a key pair
    let (decapsulation_key, encapsulation_key) = MlKem768::keygen(&mut OsRng)?;

    // Sender: Encapsulate a shared secret
    let (ciphertext, shared_secret_sender) = MlKem768::encaps(&encapsulation_key, &mut OsRng)?;

    // Receiver: Decapsulate the shared secret
    let shared_secret_receiver = MlKem768::decaps(&decapsulation_key, &ciphertext)?;

    // Both parties now have the same shared secret
    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());

    Ok(())
}
```

### ML-DSA (Digital Signatures)

```rust
use kylix_pqc::ml_dsa::{MlDsa65, Signer};
use rand::rngs::OsRng;

fn main() -> kylix_pqc::Result<()> {
    // Generate a signing key pair
    let (signing_key, verifying_key) = MlDsa65::keygen(&mut OsRng)?;

    // Sign a message
    let message = b"Hello, post-quantum world!";
    let signature = MlDsa65::sign(&signing_key, message, &mut OsRng)?;

    // Verify the signature
    MlDsa65::verify(&verifying_key, message, &signature)?;

    Ok(())
}
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| `kylix-pqc` | Main crate with re-exports |
| `kylix-core` | Core traits and utilities |
| `kylix-ml-kem` | ML-KEM (FIPS 203) implementation |
| `kylix-ml-dsa` | ML-DSA (FIPS 204) implementation |
| `kylix-cli` | Command-line interface |

## Security

**WARNING**: This library has not been audited. Use at your own risk.

See [SECURITY.md](SECURITY.md) for security policy and reporting vulnerabilities.

## Minimum Supported Rust Version

This crate requires Rust 1.75 or later.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please see [CLAUDE.md](CLAUDE.md) for project guidelines before submitting PRs.

## References

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)
