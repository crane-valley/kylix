# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.1)

### Completed

- ML-KEM-512/768/1024 (FIPS 203) with SIMD (AVX2/NEON)
- ML-DSA-44/65/87 (FIPS 204) with SIMD (AVX2/NEON)
- SLH-DSA-SHAKE all variants (FIPS 205) with parallel feature
- NIST ACVP tests, fuzz testing, CLI, no_std, constant-time, zeroization

See CHANGELOG.md for release history, BENCHMARKS.md for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| ML-DSA Verify Optimization | HIGH | See Phase 8 |
| SLH-DSA SHA2 Variants | LOW | FIPS 205 |
| SIMD NTT (WASM) | LOW | - |
| Property-based Tests | LOW | proptest |
| Security Audit | HIGH | External |

---

## Phase 4: Security Audit (Future)

**Scope:** Cryptographic correctness, side-channel resistance, memory safety, dependency audit

**Candidates:** Trail of Bits, NCC Group, Cure53, X41 D-Sec

---

## Phase 5: Ecosystem Integration (Future)

| Integration | Priority |
|-------------|----------|
| rustls/webpki | HIGH |
| PKCS#8/X.509 | HIGH |
| Python (PyO3) | MEDIUM |
| WASM bindings | MEDIUM |

---

## Phase 8: ML-DSA Verify Optimization

### Problem

ML-DSA-65 Verify: Kylix 106µs vs RustCrypto 48µs (~2x slower)

### Root Cause

Kylix recomputes on every `verify()`:
1. `expand_a()` - K×L polynomials from SHAKE128 (most expensive)
2. `hash_pk()` - SHA3-512 hash
3. `t1 << D` + `ntt()` - Scale and NTT

RustCrypto pre-computes these in `VerifyingKey` structure.

### Solution

Add `ExpandedVerificationKey` with pre-computed `a_hat`, `t1_2d_hat`, `tr`:

```rust
impl VerificationKey {
    pub fn expand(&self) -> ExpandedVerificationKey { ... }
}

impl MlDsa65 {
    pub fn verify_expanded(pk: &ExpandedVerificationKey, msg: &[u8], sig: &Signature) -> Result<()>
}
```

### Tasks

- [ ] Add `ExpandedVerificationKey` struct
- [ ] Implement `VerificationKey::expand()`
- [ ] Add `verify_expanded()` function
- [ ] Add benchmarks (regular vs expanded)

### Trade-offs

| Aspect | Current | With Expansion |
|--------|---------|----------------|
| Memory | ~2KB | ~50KB |
| Single verify | 106 µs | ~156 µs (expand+verify) |
| Repeated verify | 106 µs each | ~50 µs each |
| Break-even | - | N=2 verifications |

---

## Remaining Optimization Notes

### ML-KEM

SHA3/SHAKE is now the bottleneck (40-50% of total time). NTT/basemul SIMD complete.

### ML-DSA

SIMD complete for AVX2/NEON. WASM-SIMD128 pending (pointwise mul only).

---

## Quality Checklist

- [x] NIST ACVP compliance
- [x] Fuzz testing (daily CI)
- [x] Cross-platform CI
- [x] Constant-time operations
- [x] Zeroization
- [ ] Property-based tests
- [ ] Security audit
