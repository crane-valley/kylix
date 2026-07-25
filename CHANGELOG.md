# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release contains breaking API changes. Every item under **Changed** and
**Removed** below requires source changes in dependent code.

### Changed

- **BREAKING — ML-DSA `as_bytes` return type**: `as_bytes` on ML-DSA key and signature types now returns `&[u8]` instead of `&[u8; N]`. Callers that relied on the fixed-size array (for example passing it where `[u8; N]` was expected, or indexing past the slice API) must convert explicitly with `try_into()`.
- **BREAKING — `HashSuite` required methods**: The `*_to` methods of `kylix_slh_dsa::HashSuite` are now the required methods of the trait, and the `Vec`-returning methods are provided defaults implemented in terms of them. External implementors must implement the `*_to` methods; implementations that only provided the `Vec`-returning methods no longer compile.
- **BREAKING — SLH-DSA `sign::SecretKey` fields are private**: The fields of `kylix_slh_dsa::sign::SecretKey` are no longer public. Use the constructor and accessor methods instead of struct literals and direct field access.
- **BREAKING — ML-DSA variant module names**: The ML-DSA variant modules are renamed to `ml_dsa_44`, `ml_dsa_65`, and `ml_dsa_87`. The old `dsa44`, `dsa65`, and `dsa87` names remain as deprecated aliases and will be removed in a future release.
- **BREAKING — internal `kem` and `sign` modules are hidden**: The internal `kem` module of `kylix-ml-kem` and the `sign` modules of `kylix-ml-dsa` and `kylix-slh-dsa` are now `#[doc(hidden)]`. They are kept public only for ACVP vectors and timing harnesses. They remain `pub` and part of the public API surface, so changes to them remain semver-breaking; they are simply no longer documented and their use is discouraged.
- **BREAKING — `kylix-pqc` facade narrowed to explicit re-exports**: The facade modules re-export each item individually instead of globbing the algorithm crates, so future internal `pub` items no longer leak into the `kylix-pqc` API. Within `kylix_pqc::slh_dsa`, the SHA2 hash suites and variants are re-exported only when the `slh-dsa-sha2` feature is enabled.

  Facade retention:

  | Facade module | Kept | Removed |
  |---------------|------|---------|
  | `kylix_pqc::ml_kem` | `Kem`; `ml_kem_512`, `ml_kem_768`, `ml_kem_1024`; `MlKem512`, `MlKem768`, `MlKem1024`; `kem` (`#[doc(hidden)]`) | `Poly` |
  | `kylix_pqc::ml_dsa` | `Signer`; `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87`; deprecated `dsa44`, `dsa65`, `dsa87`; `MlDsa44`, `MlDsa65`, `MlDsa87`; `Error`, `Result`; `sign` (`#[doc(hidden)]`) | `params` |
  | `kylix_pqc::slh_dsa` | `Signer`; `Address`, `AdrsType`, `HashSuite`, `Error`, `Result`; `hash_shake` with `Shake128Hash`, `Shake192Hash`, `Shake256Hash`; `hash_sha2` with `Sha2_128Hash`, `Sha2_192Hash`, `Sha2_256Hash` (under `slh-dsa-sha2`); all 12 `slh_dsa_*` variant modules and `SlhDsa*` types; `sign` (`#[doc(hidden)]`) | `params` |

### Removed

- **BREAKING — SLH-DSA `Params` trait and marker structs**: The `Params` trait and its 12 parameter-set marker structs are removed from `kylix-slh-dsa`. Use the per-variant modules and the concrete `SlhDsa*` types instead.
- **BREAKING — `kylix_core::subtle` re-export**: `kylix-core` no longer re-exports the `subtle` crate and no longer depends on `subtle` or `thiserror`. The implicit `kylix-core/thiserror` feature is gone with them. Depend on `subtle` directly if you used the re-export.
- **BREAKING — facade re-exports of internal items**: `kylix_pqc::ml_kem::Poly`, `kylix_pqc::ml_dsa::params`, and `kylix_pqc::slh_dsa::params` are no longer reachable through the facade. They remain available from `kylix-ml-kem`, `kylix-ml-dsa`, and `kylix-slh-dsa` directly.

### Security

- **ML-KEM decapsulation-key validation**: Enforce the FIPS 203 §7.3 hash check before decapsulation and reject keys whose embedded `H(ek)` does not match the embedded encapsulation key.
- **SLH-DSA key generation cleanup**: Generate random secret seeds directly in the returned secret-key structure and zeroize deterministic key-generation seed parameters after copying them into protected storage.

### Fixed

- **Pure-signature domain separation**: Apply the required empty-context domain prefix in the public ML-DSA and SLH-DSA `Signer` implementations. Signatures created by earlier releases through these high-level APIs used the internal-algorithm message format and are not compatible with the corrected high-level verification path.

## [0.4.5] - 2026-02-11

### Security

- **Constant-time hypertree verify**: Replace `==` with `ct_eq` in `ht_verify` to prevent timing side-channel attacks during SLH-DSA signature verification (#131)
- **Constant-time polyvec norm check**: Replace early-return pattern in ML-DSA `check_norm` with constant-time accumulation using `subtle::Choice` (#131)
- **SHA-512 for SHA2 category 3/5**: Implement SHA-512 for H, T_l, PRFmsg, and Hmsg in SLH-DSA 192/256-bit SHA2 parameter sets per FIPS 205 §10.2 (#131)
- **ML-KEM input validation**: `ml_kem_encaps` and `ml_kem_decaps` now validate key lengths upfront, returning `Error::InvalidKeyLength` instead of panicking (#132)
- **FIPS 203 §7.2 ek modulus check**: Validate that all encapsulation key coefficients are in `[0, q-1]` using constant-time accumulation in `ml_kem_encaps` and `ml_kem_decaps` (#138)

### Refactored

- **SLH-DSA cfg deduplication**: Introduce `any-variant` and `any-sha2-variant` internal meta-features, replacing 12-variant `#[cfg(any(...))]` lists across 5 files (#141)
- **SLH-DSA MGF1 genericization**: Unify `mgf1_sha256`/`mgf1_sha512` into a single `mgf1<D: Digest + Clone>` generic function (#141)
- **Clippy clean**: Fix `--no-default-features` clippy warnings across all crates with proper `#[cfg]` gating (#129, #139)

### Docs

- **docs.rs metadata**: Add `all-features = true` to all crates for complete documentation on docs.rs (#140)
- **README**: Add Changelog section and SLH-DSA-SHA2 feature documentation (#132, #140)

### Dependencies

- Bump `proptest` from 1.9.0 to 1.10.0 (#136)

## [0.4.4] - 2026-02-02

### Added

- **SLH-DSA-SHA2 variants**: All 6 SHA2-based parameter sets (FIPS 205 Section 10.2) (#111)
- **Property-based tests**: Roundtrip, key/sig sizes, tampering detection using proptest (#112)

### Security

- **Eliminate intermediate buffers**: `from_bytes()` for secret key types now writes directly into struct, preventing sensitive data from lingering on the stack (#117)
- **Zeroize keygen intermediates**: Secret key bytes in `keygen()` are zeroized after use (#118)

### Performance

- **ML-DSA AVX2 Barrett reduction**: Vectorized Barrett reduction and caddq (#110)
- **SLH-DSA buffer-write API**: `_to` variants for HashSuite methods and signing functions eliminate per-call `Vec` heap allocations in hot loops (#122, #124)
- **Dev profile optimization**: `opt-level = 2` for crypto-heavy packages in dev/test builds (#125)

### Refactored

- **SLH-DSA internal storage**: Changed from struct-based to fixed-size `[u8; SIZE]` arrays for keys (#113)
- **kylix-core extraction**: Modular arithmetic macros (#119), NTT macros (#121), SIMD dispatch macros (#123) moved to shared kylix-core crate
- **ML-DSA dead code removal**: ~112 LOC removed (#109)
- **Proptest consolidation**: Unified property test suites across crates (#125)

### Fixed

- **MSRV CI**: Use `cargo check` instead of `cargo test` for MSRV validation (#114)
- **no_std builds**: Add missing `alloc` imports for SLH-DSA test modules (#120)

### Docs

- **README**: Add SLH-DSA-SHA2 variants to feature list (#116)

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

[Unreleased]: https://github.com/crane-valley/kylix/compare/v0.4.5...HEAD
[0.4.5]: https://github.com/crane-valley/kylix/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/crane-valley/kylix/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/crane-valley/kylix/compare/v0.4.2-cli...v0.4.3
[0.4.2-cli]: https://github.com/crane-valley/kylix/compare/v0.4.2...v0.4.2-cli
[0.4.2]: https://github.com/crane-valley/kylix/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/crane-valley/kylix/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/crane-valley/kylix/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/crane-valley/kylix/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/crane-valley/kylix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/crane-valley/kylix/releases/tag/v0.1.0
