# Kylix Development Roadmap

## Background

This project was inspired by [The State of OpenSSL](https://cryptography.io/en/latest/statements/state-of-openssl/) article, which highlights:

- OpenSSL 3's significant performance regressions
- Complex API design (ML-KEM encapsulation: 37 lines in OpenSSL vs 19 in BoringSSL)
- pyca/cryptography team's decision to implement ML-KEM/ML-DSA using OpenSSL alternatives
- Rust implementations achieving 10x performance improvements

Kylix aims to provide a **pure Rust, high-performance, auditable** implementation of NIST PQC standards.

---

## Current Status (v0.4.1)

### Completed

| Component | Status | Notes |
|-----------|--------|-------|
| ML-KEM-512/768/1024 | ✅ Complete | FIPS 203 compliant |
| ML-DSA-44/65/87 | ✅ Complete | FIPS 204 compliant |
| NIST ACVP Tests (ML-KEM) | ✅ Complete | Official test vectors |
| NIST ACVP Tests (ML-DSA) | ✅ Complete | KeyGen + SigVer |
| Fuzz Testing | ✅ Complete | Daily CI + 4 targets |
| CLI (keygen/encaps/decaps) | ✅ Complete | HEX/Base64/PEM support |
| CLI (sign/verify) | ✅ Complete | ML-DSA support |
| no_std Support | ✅ Complete | Embedded-ready |
| Constant-time Operations | ✅ Complete | Using `subtle` crate |
| Zeroization | ✅ Complete | Using `zeroize` crate |
| Fuzz Testing (ML-DSA) | ✅ Complete | Daily CI + 4 targets |
| Benchmarks (ML-DSA) | ✅ Complete | Criterion-based |
| SIMD Infrastructure | ✅ Complete | AVX2/NEON/WASM-SIMD128 |
| SIMD NTT (AVX2) | ✅ Complete | 8-way parallel butterflies + len=4 optimization |
| SIMD NTT (NEON) | ✅ Complete | 4-way parallel butterflies |
| SLH-DSA (SHAKE) | ✅ Complete | FIPS 205, 6 variants, parallel feature |

### Not Started

| Component | FIPS Standard | Priority |
|-----------|---------------|----------|
| ML-DSA Verify Optimization | FIPS 204 | HIGH |
| ML-KEM SIMD (Phase 2) | FIPS 203 | MEDIUM |
| SLH-DSA SHA2 Variants | FIPS 205 | LOW |
| SIMD NTT (WASM) | - | LOW |
| Property-based Tests (proptest) | - | LOW |
| Security Audit | - | HIGH |

### In Progress

| Component | Status | Notes |
|-----------|--------|-------|
| ML-KEM SIMD (Phase 1) | ✅ Complete | NTT SIMD for AVX2/NEON, ~15% improvement |

### Benchmark Results (v0.3.0 + SIMD)

Measured on Windows x86_64 (Intel i5-13500), Release build with `--features simd` and `-C target-cpu=native`:

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| ML-KEM-768 KeyGen | < 50 µs | 29.76 µs | ✅ |
| ML-KEM-768 Encaps | < 60 µs | 29.54 µs | ✅ |
| ML-KEM-768 Decaps | < 50 µs | 39.73 µs | ✅ |
| ML-DSA-65 KeyGen | - | 97 µs | ✅ |
| ML-DSA-65 Sign | < 200 µs | 165 µs | ✅ |
| ML-DSA-65 Verify | < 100 µs | 102 µs | ✅ |

#### ML-DSA Optimization Tasks

1. **NTT Optimization** - ✅ Completed with SIMD:
   - ✅ AVX2 vectorized butterfly operations (8-way parallel)
   - ✅ AVX2 len=4 layer optimization (2-group SIMD processing)
   - Precomputed twiddle factors (already in use)
   - Loop unrolling
   - Cache-friendly memory access patterns

2. **Polynomial Arithmetic** - ✅ Completed with SIMD:
   - ✅ `pointwise_acc` (matrix multiplication) using AVX2
   - ✅ AVX2 detection result caching to avoid CPUID overhead

3. **SIMD Acceleration** - ✅ AVX2 & NEON complete:
   - ✅ AVX2 for x86_64 (pointwise mul + NTT butterflies + matrix mul)
   - ✅ NEON for ARM64 (pointwise mul + NTT butterflies + matrix mul)
   - ⚠️ WASM-SIMD128 (pointwise mul only, NTT pending)

4. **Signing Loop Optimization** - No longer bottleneck:
   - With SIMD matrix multiplication, Sign performance target achieved

---

## Refactoring Opportunities

### 1. ML-KEM Variant Modules (Low Priority)

`ml_kem_512.rs`, `ml_kem_768.rs`, `ml_kem_1024.rs` contain ~645 lines of nearly identical code. Could be consolidated using:

- **Option A**: Declarative macro (`macro_rules!`) to generate boilerplate
- **Option B**: Procedural macro for more complex generation
- **Option C**: Keep as-is for explicit, readable code

**Trade-offs**:
- Macros reduce duplication but increase complexity
- Explicit code is easier to audit and debug
- Current approach works well for 3 variants

**Recommendation**: Low priority. Consider refactoring when adding ML-DSA to establish a pattern.

### 2. Dead Code Attributes (Evaluate)

Multiple modules have `#![allow(dead_code)]`:
- `encode.rs`, `hash.rs`, `kem.rs`, `k_pke.rs`, `matrix.rs`
- `ntt.rs`, `poly.rs`, `polyvec.rs`, `reduce.rs`, `sample.rs`

These may be needed for feature-gated code. Evaluate if they can be removed or scoped more narrowly.

### 3. Vec Allocations in k_pke/kem (Future)

Current implementation uses `Vec<u8>` for key/ciphertext returns. For embedded/no_std optimization, consider:
- Fixed-size array returns with const generics
- User-provided buffers to avoid allocation

---

## Phase 1: Performance & Benchmarking

### 1.1 Benchmark Infrastructure

Create `kylix-bench` crate for comprehensive benchmarking:

```
kylix-bench/
├── src/
│   ├── lib.rs
│   ├── ml_kem.rs      # ML-KEM benchmarks
│   ├── ml_dsa.rs      # ML-DSA benchmarks (future)
│   └── comparison.rs  # Cross-library comparison
├── benches/
│   ├── keygen.rs
│   ├── encaps.rs
│   └── decaps.rs
└── results/
    └── baseline.json  # Tracked baseline results
```

### 1.2 Comparison Targets

| Library | Language | Notes |
|---------|----------|-------|
| liboqs | C | Reference implementation |
| pqcrypto | Rust | Bindings to PQClean |
| oqs-rs | Rust | Bindings to liboqs |
| BoringSSL | C | Google's fork |
| AWS-LC | C | AWS fork with ML-KEM |
| OpenSSL 3.x | C | Baseline (known slow) |

### 1.3 Benchmark Metrics

- **Throughput**: Operations per second
- **Latency**: p50, p95, p99 percentiles
- **Memory**: Peak allocation, total allocated
- **Binary Size**: With/without LTO
- **Compilation Time**: Clean build time

### 1.4 CLI Benchmark Command

```bash
# Internal benchmarks
kylix bench --algorithm ml-kem-768 --iterations 10000

# Comparison mode (requires external tools installed)
kylix bench --compare --output results.json

# Generate markdown report
kylix bench --report --output BENCHMARKS.md
```

---

## Phase 2: ML-DSA Implementation ✅

### 2.1 New Crate: kylix-ml-dsa

Implemented FIPS 204 (Module-Lattice-Based Digital Signature Algorithm):

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|-----------|
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

### 2.2 Implementation Status

1. ✅ Core polynomial arithmetic (i32 coefficients for q=8380417)
2. ✅ NTT for ML-DSA parameters (9-layer, ζ=1753)
3. ✅ Signing algorithm (Algorithm 2)
4. ✅ Verification algorithm (Algorithm 3)
5. ✅ Key generation (Algorithm 1)
6. ✅ NIST ACVP test vectors (KeyGen + SigVer)
7. ✅ Fuzz targets
8. ✅ CLI integration (sign/verify commands)

### 2.3 Shared Infrastructure

Evaluate code sharing between ML-KEM and ML-DSA:

| Component | Shareable? | Notes |
|-----------|------------|-------|
| NTT | ❌ | Different modulus |
| Polynomial ops | ⚠️ Partial | Different field sizes |
| SHA3/SHAKE | ✅ | Same hash functions |
| Encoding | ⚠️ Partial | Similar bit-packing |
| Sampling | ⚠️ Partial | Different distributions |

---

## Phase 3: SLH-DSA Implementation ✅

### 3.1 New Crate: kylix-slh-dsa

Implemented FIPS 205 (Stateless Hash-Based Digital Signature Standard):

| Variant | Security | Signature Size | Status |
|---------|----------|----------------|--------|
| SLH-DSA-SHAKE-128s | Level 1 | 7,856 bytes | ✅ Complete |
| SLH-DSA-SHAKE-128f | Level 1 | 17,088 bytes | ✅ Complete |
| SLH-DSA-SHAKE-192s | Level 3 | 16,224 bytes | ✅ Complete |
| SLH-DSA-SHAKE-192f | Level 3 | 35,664 bytes | ✅ Complete |
| SLH-DSA-SHAKE-256s | Level 5 | 29,792 bytes | ✅ Complete |
| SLH-DSA-SHAKE-256f | Level 5 | 49,856 bytes | ✅ Complete |

### 3.2 Implementation Status

1. ✅ WOTS+ one-time signature (Algorithms 5-8)
2. ✅ XMSS single-layer Merkle tree (Algorithms 9-11)
3. ✅ FORS few-time signature (Algorithms 15-17)
4. ✅ Hypertree multi-layer structure (Algorithms 12-14)
5. ✅ KeyGen/Sign/Verify (Algorithms 18-20)
6. ✅ NIST ACVP test vectors (KeyGen, SigGen, SigVer)
7. ✅ Fuzz targets (4 targets)
8. ✅ Benchmarks (fast variants)
9. ✅ CLI integration (keygen/sign/verify/info/bench)
10. ✅ Rayon parallelization (`--features parallel`)
11. ⚠️ SHA2 variants (pending)

### 3.3 Architecture Notes

- Completely different from lattice-based schemes
- Based on hash functions (SHAKE128/256)
- Larger signatures but well-understood security
- Good diversity option alongside ML-DSA
- SHA2 variants not yet implemented

---

## Phase 4: Security Audit

### 4.1 Audit Scope

1. **Cryptographic Correctness**
   - Algorithm implementation vs FIPS specifications
   - Edge cases and error handling

2. **Side-Channel Resistance**
   - Timing analysis
   - Memory access patterns
   - Power analysis considerations

3. **Memory Safety**
   - Zeroization completeness
   - No uninitialized memory access
   - Buffer handling

4. **Code Quality**
   - Unsafe code review (currently none)
   - Dependency audit

### 4.2 Audit Candidates

- Trail of Bits
- NCC Group
- Cure53
- X41 D-Sec

---

## Phase 5: Ecosystem Integration

### 5.1 Protocol Integration

| Integration | Priority | Notes |
|-------------|----------|-------|
| rustls | HIGH | TLS 1.3 with PQC |
| webpki | HIGH | X.509 certificate handling |
| ring | MEDIUM | Alternative crypto backend |
| openssl-rs | LOW | FFI compatibility layer |

### 5.2 Format Support

- PKCS#8 private key encoding
- X.509 SubjectPublicKeyInfo
- CMS/PKCS#7 for signed data
- SSH key formats

### 5.3 Language Bindings

- Python (PyO3)
- JavaScript/WASM (wasm-bindgen)
- C API (cbindgen)

---

## Performance Goals

### Target: Competitive with BoringSSL/AWS-LC

Based on the OpenSSL critique, aim for:

| Operation | Target | Notes |
|-----------|--------|-------|
| ML-KEM-768 KeyGen | < 50 µs | Per operation |
| ML-KEM-768 Encaps | < 60 µs | Per operation |
| ML-KEM-768 Decaps | < 50 µs | Per operation |
| ML-DSA-65 Sign | < 200 µs | Per operation |
| ML-DSA-65 Verify | < 100 µs | Per operation |

### Optimization Strategies

1. **SIMD Acceleration** (Phase 5+)
   - AVX2/AVX-512 for x86_64
   - NEON for ARM64

2. **Assembly Optimization** (Phase 5+)
   - Critical path functions
   - Platform-specific implementations

3. **Parallelization**
   - Batch operations where applicable
   - Rayon integration for bulk processing

---

## Quality Standards

### Testing Requirements

- [x] Unit tests for all public functions
- [x] NIST ACVP compliance for all algorithms
- [x] Fuzz testing with corpus persistence
- [ ] Property-based tests (proptest)
- [x] Integration tests for CLI
- [x] Cross-platform CI (Linux, macOS, Windows)

### Documentation Requirements

- [x] API documentation (rustdoc)
- [ ] Architecture guide
- [ ] Threat model
- [ ] Performance benchmarks
- [ ] Migration guide from other libraries

### Security Requirements

- [x] No unsafe code (or audited minimal usage)
- [x] Constant-time operations for secrets
- [x] Zeroization of all sensitive data
- [x] No secret-dependent branching
- [ ] Professional security audit

---

## Release Plan: v0.4.0 ✅ Released

### New Features
- [x] SLH-DSA Rayon parallelization (`--features parallel`)
- [x] SIMD enabled by default for ML-DSA

### Documentation
- [x] SLH-DSA usage example in README
- [x] ML-DSA benchmark results in BENCHMARKS.md

### Release Checklist
- [x] Update version numbers in Cargo.toml files
- [x] Update CHANGELOG.md
- [x] Create GitHub release
- [x] Publish to crates.io

## Release: v0.4.1 ✅ Released

### Changes
- [x] Reduced package sizes by excluding ACVP test vectors from published crates
  - kylix-ml-kem: 695KB → 32KB
  - kylix-ml-dsa: 6.3MB → 38KB
  - kylix-slh-dsa: 16.7MB → excluded
- [x] Added skip logic for ACVP tests when vectors unavailable (crates.io compatibility)

---

## Phase 6: Competitive Benchmarking

### Goal
Establish Kylix as a high-performance PQC library by comparing with competitors.

### Phase 6.1: Pure Rust Comparison

**Target Libraries:**

| Library | Crate | Type | Notes |
|---------|-------|------|-------|
| RustCrypto | `ml-kem` | Pure Rust | FIPS 203, requires Rust 1.81 |
| RustCrypto | `ml-dsa` | Pure Rust | FIPS 204 |
| pqcrypto | `pqcrypto-mlkem` | C bindings | PQClean, replaces pqcrypto-kyber |
| pqcrypto | `pqcrypto-mldsa` | C bindings | PQClean |
| Cryspen | `libcrux-ml-kem` | Verified Rust | Formally verified |

**Implementation:**
- Add comparison benchmarks to `kylix-bench`
- Feature-gated dependencies for comparison targets
- Criterion-based measurement for consistency

**Output:**
```
| Library     | ML-KEM-768 KeyGen | Encaps | Decaps |
|-------------|-------------------|--------|--------|
| Kylix       | ?? µs             | ?? µs  | ?? µs  |
| RustCrypto  | ?? µs             | ?? µs  | ?? µs  |
| pqcrypto    | ?? µs             | ?? µs  | ?? µs  |
```

### Phase 6.2: CLI Comparison

**Target Tools:**
- liboqs CLI (`oqs-keygen`, `oqs-sign`)
- OpenSSL 3.x with PQC provider

**Method:**
- Use `hyperfine` for CLI benchmarking
- Measure end-to-end operation time

### Phase 6.3: Results Publication

**Venues:**
- `kylix-pqc.dev` landing page (visual graphs, highlights)
- `BENCHMARKS.md` (detailed numbers)
- GitHub Pages (CI-updated trend graphs)

**Presentation:**
- Interactive charts (Chart.js or similar)
- "X times faster than Y" highlights
- Environment details (CPU, OS, compiler)

### Phase 6.4: ML-DSA/SLH-DSA Comparison ✅ Complete

**Target Libraries:**

| Algorithm | pqcrypto | RustCrypto | libcrux |
|-----------|----------|------------|---------|
| ML-DSA | `pqcrypto-mldsa` | `ml-dsa` | `libcrux-ml-dsa` |
| SLH-DSA | N/A | `slh-dsa` | N/A |

**ML-DSA-65 Comparison Results:**

| Library | KeyGen | Sign | Verify | Notes |
|---------|--------|------|--------|-------|
| libcrux | 45.3 µs | 117.3 µs | 34.5 µs | Formally verified, fastest |
| **Kylix** | **108.5 µs** | **274.8 µs** | **115.2 µs** | Pure Rust |
| pqcrypto | 135.2 µs | 451.3 µs | 119.2 µs | C bindings (PQClean) |
| RustCrypto | 264.0 µs | 293.8 µs | 47.6 µs | Pure Rust |

**SLH-DSA-SHAKE-128f Comparison Results:**

| Library | KeyGen | Sign | Verify | Notes |
|---------|--------|------|--------|-------|
| RustCrypto | 2.35 ms | 56.3 ms | 3.34 ms | Pure Rust |
| **Kylix** | **2.82 ms** | **61.4 ms** | **3.68 ms** | Pure Rust |

**Analysis:**
- ML-DSA: Kylix is competitive with pqcrypto, ~2.5x slower than libcrux
- SLH-DSA: Kylix is ~10% slower than RustCrypto (room for optimization)
- libcrux uses formally verified, highly optimized code with platform-specific assembly

**Tasks:**
- [x] Add ML-DSA-65 comparison benchmarks
- [x] Add SLH-DSA-SHAKE-128f comparison benchmarks
- [x] Handle rand_core version differences (0.6 for ml-dsa/slh-dsa, 0.10-rc for ml-kem)

### Phase 6.5: Benchmark Results (v0.4.1)

ML-KEM-768 KeyGen comparison:

| Library | Time | vs Kylix | Notes |
|---------|------|----------|-------|
| libcrux | 12.0 µs | -60% | Formally verified, fastest |
| **Kylix** | 30.3 µs | baseline | Pure Rust |
| RustCrypto | 36.2 µs | +19% | Pure Rust |
| pqcrypto | 42.8 µs | +41% | C bindings (PQClean) |

---

## Phase 7: ML-KEM SIMD Optimization

### Goal

Close the performance gap with libcrux (currently 2.5x slower).

### Current Status: ✅ Phase 1 & 2 Complete

NTT SIMD and basemul SIMD implementations are complete with AVX2 and NEON support.

| Operation | Original | Phase 1 | Phase 2 | Total Improvement |
|-----------|----------|---------|---------|-------------------|
| ML-KEM-768 KeyGen | 30.3 µs | 29.3 µs | 29.5 µs | +3% |
| ML-KEM-768 Encaps | 29.4 µs | 27.4 µs | 24.1 µs | **+18%** |
| ML-KEM-768 Decaps | 37.3 µs | 31.2 µs | 27.9 µs | **+25%** |

### Comparison Results (v0.4.2+SIMD Phase 2)

| Library | KeyGen | Encaps | Decaps |
|---------|--------|--------|--------|
| libcrux | 12.0 µs | 10.8 µs | 10.9 µs |
| **Kylix** | **29.5 µs** | **24.1 µs** | **27.9 µs** |
| RustCrypto | 36.3 µs | 32.8 µs | 48.5 µs |
| pqcrypto | 41.5 µs | 41.5 µs | 52.2 µs |

### Completed Tasks

1. **NTT SIMD (AVX2)** ✅
   - 16-way parallel butterfly operations using i16 SIMD
   - Montgomery multiplication using mullo_epi16/mulhi_epi16
   - Forward and inverse NTT with scalar fallback for small layers

2. **NTT SIMD (NEON)** ✅
   - 8-way parallel butterfly operations
   - Same Montgomery multiplication approach
   - Full NTT implementation

3. **Barrett Reduction Optimization** ✅
   - Efficient 16-bit only Barrett reduction (pqcrystals/kyber approach)
   - AVX2: mulhi_epi16 → srai(10) → mullo_epi16 → sub_epi16
   - NEON: mulhi_s16 → vshrq(10) → vmulq → vsubq
   - ~6% performance improvement over naive 32-bit widening approach

4. **Basemul SIMD (AVX2)** ✅
   - 8 basemul operations in parallel (16 coefficients per iteration)
   - Shuffle helpers for even/odd extraction and interleaving
   - poly_basemul_acc SIMD dispatch

5. **Basemul SIMD (NEON)** ✅
   - 4 basemul operations in parallel (8 coefficients per iteration)
   - Same pattern as AVX2 implementation

### Remaining Optimization Tasks

1. **SIMD matrix-vector operations** - Priority: LOW
   - Currently poly_basemul_acc is already SIMD-accelerated
   - Further batching at matrix level may provide minor gains

2. **Memory Layout Optimization** - Priority: LOW
   - Cache-friendly coefficient ordering
   - Minimize data movement between SIMD registers

3. **Hash Function Optimization** - Priority: MEDIUM
   - SHA3/SHAKE is now the bottleneck (40-50% of total time)
   - Consider optimized SHA3 implementation

### Analysis

Combined NTT + basemul SIMD provides ~20-25% overall improvement:
- NTT/INVNTT: ~20-25% of total time (SIMD optimized)
- Basemul: ~15-20% of total time (SIMD optimized)
- Sampling (SHA3): ~40-50% of total time
- Encoding/Other: ~10-15% of total time

Further significant improvements require optimizing sampling/hashing operations (SHA3/SHAKE).

### Reference

- [libcrux-ml-kem](https://github.com/cryspen/libcrux) - Study their AVX2 implementation
- [PQClean](https://github.com/PQClean/PQClean) - Reference optimized implementations

---

## Phase 8: ML-DSA Verify Optimization

### Problem

ML-DSA-65 Verify is ~2x slower than RustCrypto (106µs vs 48µs).

| Library | Verify | Notes |
|---------|--------|-------|
| libcrux | 34.6 µs | Formally verified |
| RustCrypto | 47.6 µs | Pure Rust |
| **Kylix** | **106.3 µs** | Pure Rust |
| pqcrypto | 119.2 µs | C bindings |

### Root Cause

Kylix's `VerificationKey` stores only raw bytes:
```rust
pub struct VerificationKey {
    bytes: [u8; PK_BYTES],
}
```

Every `verify()` call recomputes:
1. `expand_a()` - Generate K×L polynomials from SHAKE128 (**most expensive**)
2. `hash_pk()` - SHA3-512 hash of public key
3. `t1 << D` + `ntt()` - Scale and NTT transform

RustCrypto pre-computes these in `VerifyingKey`:
```rust
pub struct VerifyingKey<P> {
    A_hat: NttMatrix<P::K, P::L>,  // expand_a result
    t1_2d_hat: NttVector<P::K>,    // t1*2^d NTT
    tr: B64,                        // hash_pk result
}
```

### Solution: ExpandedVerificationKey

Add a new structure for repeated verification:

```rust
pub struct ExpandedVerificationKey {
    rho: [u8; 32],
    t1: PolyVecK<K>,
    // Pre-computed values
    a_hat: MatrixK<K, L>,           // expand_a result (NTT domain)
    t1_2d_hat: PolyVecK<K>,         // t1 * 2^D in NTT domain
    tr: [u8; 64],                   // H(pk)
}

impl VerificationKey {
    /// Expand for fast repeated verification
    pub fn expand(&self) -> ExpandedVerificationKey { ... }
}

impl MlDsa65 {
    /// Fast verify using pre-expanded key
    pub fn verify_expanded(
        pk: &ExpandedVerificationKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> { ... }
}
```

### Tasks

- [ ] Add `ExpandedVerificationKey` struct with pre-computed fields
- [ ] Implement `VerificationKey::expand()` method
- [ ] Add `verify_expanded()` function using pre-computed values
- [ ] Add benchmarks comparing regular vs expanded verify
- [ ] Update documentation with usage examples

### Trade-offs

| Aspect | Current | With Expansion |
|--------|---------|----------------|
| Memory | ~2KB (bytes only) | ~50KB (with A_hat) |
| First verify | 106 µs | ~106 µs (expand) + ~50 µs (verify) |
| Repeated verify | 106 µs each | ~50 µs each |
| API complexity | Simple | Two verify methods |

### Use Cases

Best for scenarios with repeated verification:
- Certificate validation (same CA key, many certs)
- Batch signature verification
- Long-lived server verification keys

### Expected Results

After optimization:
- `verify_expanded()`: ~50 µs (matching RustCrypto)
- Total for N verifications: 106 + 50×(N-1) µs vs 106×N µs
- Break-even point: N=2 verifications

---

## Contributing

Priority areas for contribution:

1. Performance optimization
2. Competitive benchmarking
3. Platform-specific testing
4. Documentation improvements
5. Integration examples
