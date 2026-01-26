# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **CLI bench feature extraction**: Benchmark functionality moved to optional `bench` feature
  - Reduces binary size and attack surface for production builds
  - Enable with `cargo install --path kylix-cli --features bench`
- **Binary distribution**: Added cargo-dist for automated GitHub Releases
  - Pre-built binaries for Linux (x64, ARM64), macOS (x64, ARM64), Windows (x64)
  - One-command installation via shell/PowerShell scripts

### Security

- **CLI secret key file permissions**: Secret keys written with 0o600 permissions on Unix
  - Uses atomic temp file + rename pattern to prevent race conditions
  - Random suffix in temp filename prevents predictable file attacks
- **CLI zeroization improvements**: Consistent zeroization of sensitive data across all commands
  - `cmd_keygen`: Zeroizes `sk_bytes` after encoding
  - `cmd_encaps`: Zeroizes `ss_bytes` after output
  - `cmd_decaps`: Zeroizes `sk_data`, `sk_bytes`, and `ss_bytes`
- **Doc example validation**: Changed doc examples from `ignore` to `no_run` for compile-time validation

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

[Unreleased]: https://github.com/crane-valley/kylix/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/crane-valley/kylix/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/crane-valley/kylix/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/crane-valley/kylix/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/crane-valley/kylix/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/crane-valley/kylix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/crane-valley/kylix/releases/tag/v0.1.0
