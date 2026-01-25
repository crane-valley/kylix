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
| ML-KEM SIMD Optimization | FIPS 203 | HIGH |
| SLH-DSA SHA2 Variants | FIPS 205 | LOW |
| SIMD NTT (WASM) | - | LOW |
| Property-based Tests (proptest) | - | LOW |
| Security Audit | - | HIGH |

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

### Phase 6.4: Benchmark Results (v0.4.1)

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

### Target

| Operation | Current | Target | Improvement |
|-----------|---------|--------|-------------|
| ML-KEM-768 KeyGen | 30 µs | < 15 µs | 2x |
| ML-KEM-768 Encaps | 29 µs | < 15 µs | 2x |
| ML-KEM-768 Decaps | 40 µs | < 20 µs | 2x |

### Tasks

1. **NTT SIMD (AVX2)** - Priority: HIGH
   - Port ML-DSA SIMD NTT infrastructure to ML-KEM
   - Adapt for ML-KEM's different modulus (q=3329 vs q=8380417)
   - 8-way parallel butterfly operations

2. **NTT SIMD (NEON)** - Priority: MEDIUM
   - ARM64 4-way parallel butterflies
   - Same approach as ML-DSA

3. **Polynomial Arithmetic** - Priority: HIGH
   - Vectorized pointwise multiplication
   - SIMD matrix-vector operations

4. **Memory Layout Optimization** - Priority: MEDIUM
   - Cache-friendly coefficient ordering
   - Minimize data movement between SIMD registers

### Implementation Notes

- ML-KEM uses smaller modulus (q=3329) than ML-DSA (q=8380417)
- 16-bit coefficients fit 16 values per AVX2 register (vs 8 for ML-DSA)
- Potential for even greater SIMD speedup than ML-DSA

### Reference

- [libcrux-ml-kem](https://github.com/cryspen/libcrux) - Study their AVX2 implementation
- [PQClean](https://github.com/PQClean/PQClean) - Reference optimized implementations

---

## Contributing

Priority areas for contribution:

1. Performance optimization
2. Competitive benchmarking
3. Platform-specific testing
4. Documentation improvements
5. Integration examples
