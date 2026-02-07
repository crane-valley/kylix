# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.4)

### Completed

- ML-KEM-512/768/1024 (FIPS 203) with SIMD (AVX2/NEON) optimizations for NTT, basemul, and Barrett reduction
- ML-DSA-44/65/87 (FIPS 204) with SIMD (AVX2/NEON) and expanded verification
- SLH-DSA-SHAKE all variants (FIPS 205) with parallel feature
- SLH-DSA-SHA2 all variants (FIPS 205 Section 10.2)
- NIST ACVP tests, fuzz testing, no_std, constant-time, zeroization
- Key type wrapper macros (`define_kem_types!` / `define_dsa_types!` / `define_slh_dsa_variant!`)
- Dudect timing tests for constant-time verification
- Dudect CI integration (ML-KEM regression detection)
- Benchmark stability with fixed seed (kylix-cli)
- Core shared macros: modular arithmetic (Barrett/Montgomery), NTT, SIMD dispatch in kylix-core
- SLH-DSA buffer-write API (`_to` variants for signing functions and HashSuite trait)
- Intermediate buffer cleanup (direct-write `from_bytes()`, keygen zeroization)
- Dev profile optimization and proptest consolidation with macros
- Clippy fixes: `#[cfg(test)]` for test-only code, `.div_ceil()`, removed unnecessary lint suppression

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| FIPS 203 ek Modulus Check | MEDIUM | Section 7.3: verify each coefficient of decoded ek is in [0, q-1]. Currently only length validation is performed (PR #132). |
| SIMD NTT (WASM) | LOW | - |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| API: Key/Sig Bytes Method | LOW | Consistency | Unify `as_bytes()` vs `to_bytes()` across crates (see note below) |
| SLH-DSA: wots_pk_gen_to / wots_pk_from_sig_to | LOW | Performance | Add `_to` buffer-write variants for `wots_pk_gen` and `wots_pk_from_sig` to eliminate their single Vec return allocation. Low priority since these are called once per WOTS+ operation (not in hot loops). |
| Poly API Consistency | MEDIUM | Ergonomics | ML-KEM uses module functions (`poly_add()`), ML-DSA uses methods (`.add()`). Standardize to methods |
| k_pke Internal Validation | LOW | Defense-in-depth | `k_pke_encrypt`/`k_pke_decrypt` accept `&[u8]` with no length validation; panics on short input via `try_into().unwrap()`. Currently protected by ML-KEM layer validation (PR #132), but direct `pub(crate)` callers are unguarded. |

#### API Consistency Note

ML-KEM/ML-DSA use `as_bytes() -> &[u8]`, SLH-DSA uses `to_bytes()` with mixed semantics:
- `SigningKey.to_bytes() -> Zeroizing<Vec<u8>>` (owned, OK)
- `VerificationKey.to_bytes() -> Vec<u8>` (owned, OK)
- `Signature.to_bytes() -> &[u8]` (borrowed, **should be `as_bytes()`** per Rust convention)

Recommended fix: Add `as_bytes()` methods returning `&[u8]` for all types, deprecate inconsistent `to_bytes()` on `Signature`.

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
- Zeroize intermediate secrets in `ml_kem_encaps`/`ml_kem_decaps` (`g_input`, `k_prime`, `r_prime`, `m_prime`, `r`, `shared_secret`) — stack-allocated but not explicitly zeroized on function return

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
- [x] Property-based tests (proptest: roundtrip, key/sig sizes, tampering detection)
- [ ] Fuzz targets for error/validation paths (invalid-length inputs to encaps/decaps)
- [ ] Constant-time formal verification
- [ ] Security audit
