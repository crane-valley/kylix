# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

This roadmap is intentionally scoped for an experimental PoC. The focus is on
performance and implementation quality improvements that a coding agent can
drive directly. Tasks that mainly improve production ecosystem compatibility,
packaging, or audit readiness are deferred unless the project direction changes.

---

## Current Status (v0.4.5)

### Completed

- **Algorithms**: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA-SHAKE/SHA2 all variants (FIPS 205)
- **Performance**: SIMD (AVX2/NEON) for NTT, basemul, Barrett reduction, pointwise mul; ML-DSA WASM-SIMD128 pointwise mul; ML-DSA expanded verification; SLH-DSA parallel feature; benchmark stability (kylix-cli)
- **Quality**: ACVP tests, fuzz testing, no_std, constant-time (`subtle`/dudect), zeroization, proptest, clippy clean (`--all-features` and `--no-default-features`)
- **Infrastructure**: Core shared macros (kylix-core), key type wrapper macros, buffer-write API (`_to` variants), dudect CI
- **Security fixes**: Constant-time hypertree verify (`ct_eq`), constant-time polyvec `check_norm` (`Choice`), SHA-512 for SHA2 category 3/5 (FIPS 205 §10.2), FIPS 203 §7.2 ek modulus check in `ml_kem_encaps`/`ml_kem_decaps`, `ml_dsa_verify` public-key length check (commit 212c030)
- **API**: `as_bytes()` on all key types via the shared `kylix_core::impl_fixed_bytes!` macro. Not yet unified in return type: ML-KEM and SLH-DSA return `&[u8]`, ML-DSA still returns fixed-size array references (`&[u8; N]`). Unifying ML-DSA is a public-surface change reserved for 0.5.0.
- **Refactoring**: ML-DSA sign.rs function splitting (PR #143) — extracted helpers, removed debug `eprintln!`, added zeroization on failure path

> See `CHANGELOG.md` for full release history and `BENCHMARKS.md` for performance data.

### Near-Term Priorities

| Component | Priority | Notes |
|-----------|----------|-------|
| SHA3/SHAKE SIMD Optimization | HIGH | Keccak permutation AVX2 — SHA3/SHAKE is 40-50% of ML-KEM total time. No Rust PQC lib has this yet (differentiation opportunity). |
| Fuzz Targets for Error/Validation Paths | HIGH | Add coverage for malformed and invalid-length inputs to encaps/decaps and related parsing paths. High-value quality work that is easy to automate and verify in CI. |
| k_pke Internal Validation | HIGH | Prevent short-input panics in internal encryption/decryption helpers. Good defense-in-depth with limited implementation cost. |
| SIMD NTT (WASM) | LOW | ML-DSA pointwise mul done; NTT not yet WASM-optimized. ML-KEM has no WASM SIMD. |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| ML-DSA: Nonce u16 Overflow at High Iteration Count | LOW | Correctness | In `ml_dsa_sign`, `nonce as u16` truncates for ML-DSA-87 (L=7) when `kappa > 9362` (nonce = kappa\*L+i > 65535). Astronomically unlikely to reach but technically incorrect. Consider using `u32` nonces or lowering `MAX_ATTEMPTS`. Pre-existing issue, not introduced by sign.rs refactor. |
| Poly API Consistency | LOW | Ergonomics | ML-KEM uses module functions (`poly_add()`), ML-DSA uses methods (`.add()`). Standardize only if the API churn is worth it. |
| SLH-DSA: parallel/sequential Sign Dedup | LOW | Code quality | `slh_sign_impl()` has parallel and sequential versions (~90 lines each) that differ only in trait bounds (`Send + Sync`), FORS sign function call, and address mutability semantics. Unification is non-trivial due to Rust's inability to conditionally apply trait bounds. |
| SLH-DSA: wots_pk_gen_to / wots_pk_from_sig_to | LOW | Performance | Add `_to` buffer-write variants for `wots_pk_gen` and `wots_pk_from_sig` to eliminate their single Vec return allocation. Low priority since these are called once per WOTS+ operation (not in hot loops). |

---

## Optional Verification Work

These items matter if Kylix moves beyond a PoC and starts targeting outside
adoption or production-adjacent use. They are intentionally separated from the
agent-friendly implementation backlog above.

### Constant-time Verification

Dudect-based timing tests in `timing/` directory.
- ML-KEM decaps: passes (max t < 4.5)
- ML-DSA sign: expected variance (rejection sampling)

**Future work:**
- ML-KEM `check_ek_modulus` dudect test (LOW — verify CT property of coefficient scan under release LTO)
- ML-DSA subroutine-level timing tests (NTT, poly ops, secret vector operations)
- SLH-DSA timing tests (LOW — inherently constant-time hash-based design)
- Formal verification (ct-verif / ctgrind) for critical paths
- Zeroize intermediate secrets in `ml_kem_encaps`/`ml_kem_decaps` (stack-allocated `g_input`, `k_prime`, `r_prime`, `m_prime`, `r`, `shared_secret`)

---

## Optimization Notes

### ML-KEM

SHA3/SHAKE is now the bottleneck (40-50% of total time). NTT/basemul SIMD complete. No Rust SHA3 crate offers SIMD-optimized Keccak permutation as of 2026-02 — implementing AVX2 Keccak (e.g., 2-3x faster SHA3/SHAKE) could yield roughly 1.3-1.6x overall speedup.

### ML-DSA

SIMD complete for AVX2/NEON. WASM-SIMD128 done for pointwise mul; NTT not yet WASM-optimized.

### Competitive Positioning

Benchmarks (ML-KEM-768 Encaps, Intel i5-13500 AVX2):
- libcrux (formally verified + ASM): ~11 µs
- **Kylix**: ~23 µs — **~1.4x faster than RustCrypto**
- RustCrypto ml-kem: ~33 µs
- pqcrypto (C FFI): ~42 µs

Primary optimization opportunity: SHA3/SHAKE SIMD (HIGH priority, biggest single improvement possible).

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
- [x] `unsafe_op_in_unsafe_fn` denied across workspace (SIMD modules explicitly allowed)
- [x] `clippy::unwrap_used` / `clippy::expect_used` denied across workspace (justified uses annotated)
- [x] Property-based tests (proptest: roundtrip, key/sig sizes, tampering detection)
- [x] CLAUDE.md expansion (SIMD, dudect, CI, crate graph) + docs/ARCHITECTURE.md
- [ ] Fuzz targets for error/validation paths (invalid-length inputs to encaps/decaps)
