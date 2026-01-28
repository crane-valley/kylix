# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.3)

### Completed

- ML-KEM-512/768/1024 (FIPS 203) with SIMD (AVX2/NEON) optimizations for NTT, basemul, and Barrett reduction
- ML-DSA-44/65/87 (FIPS 204) with SIMD (AVX2/NEON) and expanded verification
- SLH-DSA-SHAKE all variants (FIPS 205) with parallel feature
- NIST ACVP tests, fuzz testing, no_std, constant-time, zeroization
- Key type wrapper macros (`define_kem_types!` / `define_dsa_types!` / `define_slh_dsa_variant!`)
- Dudect timing tests for constant-time verification
- Dudect CI integration (ML-KEM regression detection)
- Benchmark stability with fixed seed (kylix-cli)

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| SLH-DSA SHA2 Variants | LOW | FIPS 205 |
| SIMD NTT (WASM) | LOW | - |
| Property-based Tests | LOW | proptest |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| ~~Lib: Dead Code Audit~~ | ~~MEDIUM~~ | ~~Clarity~~ | ✓ Removed ~112 LOC from kylix-ml-dsa |
| ~~Lib: SLH-DSA Variants~~ | ~~LOW~~ | ~~~600 LOC~~ | ✓ Consolidated with `define_slh_dsa_variant!` macro |
| ~~ML-DSA: AVX2 Barrett~~ | ~~LOW~~ | ~~Performance~~ | ✓ Vectorized Barrett reduction and caddq in `simd/avx2.rs` |

---

## Phase 4: Security Audit (Future)

**Scope:** Cryptographic correctness, side-channel resistance, memory safety, dependency audit

**Candidates:** Trail of Bits, NCC Group, Cure53, X41 D-Sec

### Constant-time Verification

**Status:** Added dudect-based timing tests in `timing/` directory.

**Results:**
- **ML-KEM decaps**: ✅ Passes (max t < 4.5) - implicit rejection is constant-time
- **ML-DSA sign**: ⚠️ Expected variance due to rejection sampling loop

**Running tests:**
```bash
cd timing && cargo run --release --bin ml_kem
cd timing && cargo run --release --bin ml_dsa
```

**Future work:**
- Add ML-DSA subroutine-level timing tests (NTT, poly ops, secret vector operations)
- SLH-DSA timing tests (LOW priority) - hash-based design is inherently constant-time, very slow execution
- Formal verification with ct-verif or ctgrind for critical paths

---

## Phase 5: Ecosystem Integration (Future)

| Integration | Priority |
|-------------|----------|
| rustls/webpki | HIGH |
| PKCS#8/X.509 | HIGH |
| Python (PyO3) | MEDIUM |
| WASM bindings | MEDIUM |

---

## Optimization Notes

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
- [x] Dudect timing tests (ML-KEM passes, ML-DSA expected variance due to rejection sampling)
- [x] Dudect CI integration (ML-KEM regression detection)
- [x] cargo-audit in CI
- [ ] Property-based tests
- [ ] Constant-time formal verification
- [ ] Security audit
