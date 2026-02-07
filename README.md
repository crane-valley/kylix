# Kylix

[![CI](https://github.com/crane-valley/kylix/actions/workflows/ci.yml/badge.svg)](https://github.com/crane-valley/kylix/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/kylix-pqc.svg)](https://crates.io/crates/kylix-pqc)
[![Documentation](https://docs.rs/kylix-pqc/badge.svg)](https://docs.rs/kylix-pqc)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fkylix-pqc.dev%2F)](https://kylix-pqc.dev/)
[![Benchmarks](https://img.shields.io/badge/Benchmarks-GitHub%20Pages-orange)](https://crane-valley.github.io/kylix-cli/dev/bench/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.75-blue.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

A post-quantum cryptography library implementing NIST FIPS standards in pure Rust.

## Security

> [!WARNING]
> This library is experimental and has **NOT been audited**. It is **NOT intended for production use**.

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## Features

- **ML-KEM** (FIPS 203): Module-Lattice-Based Key Encapsulation Mechanism
  - ML-KEM-512 (Security Level 1)
  - ML-KEM-768 (Security Level 3)
  - ML-KEM-1024 (Security Level 5)
- **ML-DSA** (FIPS 204): Module-Lattice-Based Digital Signature Algorithm
  - ML-DSA-44 (Security Level 2)
  - ML-DSA-65 (Security Level 3)
  - ML-DSA-87 (Security Level 5)
- **SLH-DSA** (FIPS 205): Stateless Hash-Based Digital Signature Algorithm
  - SHAKE-based variants (enabled by default):
    - SLH-DSA-SHAKE-128s/128f (Security Level 1)
    - SLH-DSA-SHAKE-192s/192f (Security Level 3)
    - SLH-DSA-SHAKE-256s/256f (Security Level 5)
  - SHA2-based variants (requires `slh-dsa-sha2` feature):
    - SLH-DSA-SHA2-128s/128f (Security Level 1)
    - SLH-DSA-SHA2-192s/192f (Security Level 3)
    - SLH-DSA-SHA2-256s/256f (Security Level 5)
- `no_std` compatible for embedded systems
- Constant-time implementations to prevent timing attacks
- Secure memory handling with automatic zeroization
- SIMD optimizations (AVX2/NEON) for high performance
- Comprehensive test coverage including NIST ACVP vectors

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kylix-pqc = "0.4"
```

To enable SHA2-based SLH-DSA variants:

```toml
[dependencies]
kylix-pqc = { version = "0.4", features = ["slh-dsa-sha2"] }
```

## Usage

### ML-KEM (Key Encapsulation)

```rust
use kylix_pqc::ml_kem::{MlKem768, Kem};
use rand::rng;

fn main() -> kylix_pqc::Result<()> {
    let mut rng = rng();

    // Generate a key pair
    let (decapsulation_key, encapsulation_key) = MlKem768::keygen(&mut rng)?;

    // Sender: Encapsulate a shared secret
    let (ciphertext, shared_secret_sender) = MlKem768::encaps(&encapsulation_key, &mut rng)?;

    // Receiver: Decapsulate the shared secret
    let shared_secret_receiver = MlKem768::decaps(&decapsulation_key, &ciphertext)?;

    // Both parties now have the same shared secret
    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());

    Ok(())
}
```

### ML-DSA (Digital Signatures)

```rust
use kylix_pqc::ml_dsa::MlDsa65;
use rand::rng;

fn main() -> kylix_pqc::Result<()> {
    let mut rng = rng();

    // Generate a signing key pair
    let (signing_key, verifying_key) = MlDsa65::keygen(&mut rng)?;

    // Sign a message (deterministic signing, no RNG needed)
    let message = b"Hello, post-quantum world!";
    let signature = MlDsa65::sign(&signing_key, message)?;

    // Verify the signature
    MlDsa65::verify(&verifying_key, message, &signature)?;

    Ok(())
}
```

### SLH-DSA (Stateless Hash-Based Signatures)

```rust
use kylix_pqc::slh_dsa::SlhDsaShake128f;
use rand::rng;

fn main() -> kylix_pqc::Result<()> {
    let mut rng = rng();

    // Generate a signing key pair
    let (signing_key, verifying_key) = SlhDsaShake128f::keygen(&mut rng)?;

    // Sign a message (deterministic signing, no RNG needed)
    let message = b"Hello, post-quantum world!";
    let signature = SlhDsaShake128f::sign(&signing_key, message)?;

    // Verify the signature
    SlhDsaShake128f::verify(&verifying_key, message, &signature)?;

    Ok(())
}
```

## Command-Line Interface

The `kylix` CLI is available in a separate repository: [crane-valley/kylix-cli](https://github.com/crane-valley/kylix-cli)

```bash
# Install via shell script (Linux/macOS)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/crane-valley/kylix-cli/releases/latest/download/kylix-cli-installer.sh | sh

# Install via PowerShell (Windows)
powershell -ExecutionPolicy ByPass -c "irm https://github.com/crane-valley/kylix-cli/releases/latest/download/kylix-cli-installer.ps1 | iex"

# Or install from source
cargo install --git https://github.com/crane-valley/kylix-cli kylix-cli
```

See the [kylix-cli repository](https://github.com/crane-valley/kylix-cli) for full usage documentation.

## Crate Structure

| Crate | Description |
|-------|-------------|
| `kylix-pqc` | Main crate with re-exports |
| `kylix-core` | Core traits and utilities |
| `kylix-ml-kem` | ML-KEM (FIPS 203) implementation |
| `kylix-ml-dsa` | ML-DSA (FIPS 204) implementation |
| `kylix-slh-dsa` | SLH-DSA (FIPS 205) implementation |

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
