# Kylix Architecture

## Overview

Kylix is a pure-Rust implementation of NIST Post-Quantum Cryptography standards.
It provides ML-KEM (key encapsulation), ML-DSA (digital signatures), and
SLH-DSA (stateless hash-based signatures) with hardware-accelerated SIMD support.

Published as `kylix-pqc` on crates.io. MSRV: 1.75.

## Workspace Structure

| Crate | FIPS | Purpose |
|-------|------|---------|
| kylix-core | -- | Shared primitives: NTT macros, Barrett reduction, SIMD dispatch |
| kylix-ml-kem | 203 | ML-KEM (Kyber): key encapsulation mechanism |
| kylix-ml-dsa | 204 | ML-DSA (Dilithium): digital signature scheme |
| kylix-slh-dsa | 205 | SLH-DSA (SPHINCS+): hash-based signatures |
| kylix | -- | Re-export facade published as `kylix-pqc` |

Excluded from workspace: `timing/` (dudect tests), `fuzz/` (cargo-fuzz targets)

## Shared Patterns

### NTT (Number Theoretic Transform)

All lattice-based schemes (ML-KEM, ML-DSA) use NTT for polynomial multiplication.
Each crate has its own NTT with scheme-specific modulus and roots of unity:
- ML-KEM: q = 3329
- ML-DSA: q = 8380417

SIMD-accelerated variants in `{crate}/src/simd/avx2.rs` and `{crate}/src/simd/neon.rs`.

### SIMD Dispatch

Runtime detection with compile-time fast paths (see kylix-core/src/simd.rs):
- AVX2: x86_64, `is_x86_feature_detected!` with `#[target_feature]` functions
- NEON: aarch64, always available
- WASM-SIMD128: wasm32, feature-gated
- Scalar: universal fallback, no_std compatible

### Key Types

All key types (public key, secret key, ciphertext, signature) follow:
- `from_bytes(&[u8]) -> Result<Self, Error>` with input validation
- `as_bytes() -> &[u8]` for zero-copy access
- Secret key types implement `Zeroize + ZeroizeOnDrop`

### Constant-Time Operations

- All secret-dependent logic uses `subtle` crate (Choice, ConditionallySelectable, ct_eq)
- No branching on secret data
- Verified via dudect timing tests (timing/ directory)
- ML-DSA sign uses rejection sampling (inherently variable-time for public output)

## Algorithm-Specific Notes

### ML-KEM (FIPS 203)

- Security levels: 512 (Cat 1), 768 (Cat 3), 1024 (Cat 5)
- FIPS 203 section 7.2: modulus check in encaps/decaps
- decaps passes dudect constant-time tests (|max t| < 4.5)

### ML-DSA (FIPS 204)

- Security levels: 44 (Cat 2), 65 (Cat 3), 87 (Cat 5)
- sign.rs uses Zeroizing<T> wrappers (refactored PR #148, replaced 76+ manual .zeroize() calls)
- WASM-SIMD128 implemented for pointwise multiplication

### SLH-DSA (FIPS 205)

- Hash-based (no lattice), stateless
- Two hash families: SHAKE (default) and SHA2 (feature flag `sha2`)
- Two speed tiers: f (fast, larger signatures) and s (small, slower)
- `parallel` feature for multi-threaded signing (Rayon)
- Inherently constant-time (hash-based design, no secret-dependent branches)
- 10-15x slower at opt-level=0; dev/test profiles use opt-level=2
