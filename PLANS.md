# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.1)

### Completed

- ML-KEM-512/768/1024 (FIPS 203) with SIMD (AVX2/NEON)
- ML-DSA-44/65/87 (FIPS 204) with SIMD (AVX2/NEON)
- SLH-DSA-SHAKE all variants (FIPS 205) with parallel feature
- NIST ACVP tests, fuzz testing, CLI, no_std, constant-time, zeroization

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
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

## Phase 8: ML-DSA Verify Optimization ✓

**Completed.** Added `ExpandedVerificationKey` with pre-computed values for fast repeated verification.

### Results

| Variant | expand() | regular | expanded | Speedup |
|---------|----------|---------|----------|---------|
| ML-DSA-44 | 37.7 µs | 63.5 µs | 30.4 µs | 2.1x |
| ML-DSA-65 | 68.1 µs | 100.5 µs | 38.4 µs | 2.6x |
| ML-DSA-87 | 162.8 µs | 164.6 µs | 55.6 µs | 3.0x |

Break-even: 2 verifications with the same key.

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
