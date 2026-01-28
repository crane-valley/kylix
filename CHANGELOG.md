# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3] - 2026-01-28

### Changed

- **SLH-DSA SigningKey::to_bytes()**: Now returns `Zeroizing<Vec<u8>>` instead of `Vec<u8>`
  - Automatic memory zeroization on drop for improved security
  - Performance improvement by eliminating unnecessary allocation and copy
  - **BREAKING**: Callers can use the bytes via `Deref` (e.g., `&*sk_bytes`)
- **Doc example validation**: Changed doc examples from `ignore` to `no_run` for compile-time validation

### Refactored

- **SLH-DSA variant consolidation**: Replaced 6 variant files (~1,050 LOC) with `define_slh_dsa_variant!` macro
  - Each variant file reduced from ~170 lines to ~15 lines
  - Single point of maintenance for all SLH-DSA implementations

### Security

- **PRF output zeroization (SLH-DSA)**: `prf()` and `prf_msg()` now return `Zeroizing<Vec<u8>>`
  - Ensures automatic memory cleanup of one-time secret keys

### Performance

- **Buffer allocation optimizations**: Reduced allocations in ML-KEM and ML-DSA
  - ML-KEM: Reuse PRF output buffers, remove unnecessary clone
  - ML-DSA: Reuse packing buffers with explicit zeroization for secret material

### CI

- **cargo-audit**: Added RustSec security audit to CI pipeline
- **Dudect CI**: Added ML-KEM constant-time regression detection (fails if |max t| > 4.5)

## [0.4.2-cli] - 2026-01-27

CLI-only release with security improvements and new features.

### Added

- **Binary distribution**: Automated GitHub Releases via cargo-dist
  - Pre-built binaries for Linux (x64, ARM64), macOS (x64, ARM64), Windows (x64)
  - One-command installation via shell/PowerShell scripts
- **Benchmark comparison**: Compare Kylix performance against external PQC libraries
  - OpenSSL 3.x (oqs-provider) and liboqs support
  - Cross-platform library detection (Windows vcpkg, macOS Homebrew, Linux system paths)
  - Run with `kylix bench --compare --algo <algorithm>`

### Changed

- **Bench feature extraction**: Benchmark functionality moved to optional `bench` feature
  - Reduces binary size and attack surface for production builds
  - Enable with `cargo install --path kylix-cli --features bench`
- **AlgorithmInfo refactoring**: Centralized algorithm metadata for cleaner code

### Security

- **Secure secret key file writing (Unix)**: Keys written with `0o600` permissions using atomic temp-file-and-rename pattern
  - Prevents race conditions and partial writes
  - Random suffix in temp filename prevents predictable file-path attacks
- **Zeroization improvements**: Consistent zeroization of sensitive data across all commands
  - `cmd_keygen`: Zeroizes `sk_bytes` after encoding
  - `cmd_encaps`: Zeroizes `ss_bytes` after output
  - `cmd_decaps`: Zeroizes `sk_data`, `sk_bytes`, and `ss_bytes`

## [0.4.2] - 2026-01-25

### Added

- **ML-KEM SIMD optimizations**: AVX2 for x86_64, NEON for ARM64
  - 16-way parallel NTT operations using i16 SIMD intrinsics
  - Basemul SIMD optimization for polynomial multiplication
  - Efficient Barrett reduction using pqcrystals/kyber approach
  - Performance improvement (ML-KEM-768): ~16% faster Decaps, ~7% faster Encaps
  - SIMD enabled by default with runtime CPU feature detection
- **ML-DSA expanded verification**: Pre-expand verification key for fast repeated verification
  - `ExpandedVerificationKey` type with `expand()` and `verify_expanded()` methods
  - Amortizes key expansion cost (~68µs for ML-DSA-65) across multiple verifications
  - Useful for batch verification, certificate chain validation, repeated verification scenarios

## [0.4.1] - 2026-01-25

### Changed

- **Reduced package sizes**: Excluded ACVP test vectors from published crates
  - kylix-ml-kem: 695KB → 32KB
  - kylix-ml-dsa: 6.3MB → 38KB
  - Tests still run from git repository

## [0.4.0] - 2026-01-25

### Added

- **SLH-DSA (FIPS 205)**: Complete implementation of Stateless Hash-Based Digital Signature Algorithm
  - All 6 SHAKE variants: 128s/128f, 192s/192f, 256s/256f
  - NIST ACVP test vectors (KeyGen, SigGen, SigVer)
  - CLI support (keygen, sign, verify, info, bench)
  - Fuzz testing (4 targets)
- **SLH-DSA parallel feature**: Multi-threaded FORS computation using Rayon (`--features parallel`)
  - Parallelizes K independent FORS trees during signing
  - Significant speedup on multi-core systems
- **ML-DSA enhancements**:
  - **SIMD optimizations**: AVX2 for x86_64, NEON for ARM64 (NTT butterflies, matrix multiplication)
  - ACVP tests, CLI sign/verify commands, fuzz testing, benchmarks

### Changed

- **SIMD enabled by default for ML-DSA**: The `simd` feature is now included in default features
  - Uses runtime CPU feature detection (AVX2/NEON) for safety
  - No action required; disable with `default-features = false` if needed
- Improved NTT performance with SIMD vectorization
- Updated benchmark infrastructure

### Documentation

- Added SLH-DSA usage example to README.md
- Added ML-DSA benchmark results to BENCHMARKS.md
- Updated benchmark running instructions

## [0.3.0] - 2026-01-24

### Added

- **ML-DSA (FIPS 204)**: Complete implementation of Module-Lattice-Based Digital Signature Algorithm
  - All 3 variants: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **ML-KEM additions**:
  - CLI commands (keygen, encaps, decaps)
  - NIST ACVP tests
  - Fuzzing infrastructure
  - Criterion benchmarks

## [0.2.0] - 2026-01-22

### Added

- **ML-KEM (FIPS 203)**: Complete implementation of KeyGen, Encaps, Decaps
  - All 3 variants: ML-KEM-512, ML-KEM-768, ML-KEM-1024

## [0.1.0] - 2026-01-22

### Added

- Initial project structure for post-quantum cryptography library
- ML-KEM (FIPS 203) foundation modules
- `no_std` support
- Constant-time operations using `subtle` crate
- Zeroization of sensitive data using `zeroize` crate

[Unreleased]: https://github.com/crane-valley/kylix/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/crane-valley/kylix/compare/v0.4.2-cli...v0.4.3
[0.4.2-cli]: https://github.com/crane-valley/kylix/compare/v0.4.2...v0.4.2-cli
[0.4.2]: https://github.com/crane-valley/kylix/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/crane-valley/kylix/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/crane-valley/kylix/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/crane-valley/kylix/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/crane-valley/kylix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/crane-valley/kylix/releases/tag/v0.1.0
