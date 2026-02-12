# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.4)

### Completed

- **Algorithms**: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA-SHAKE/SHA2 all variants (FIPS 205)
- **Performance**: SIMD (AVX2/NEON) for NTT, basemul, Barrett reduction, pointwise mul; ML-DSA expanded verification; SLH-DSA parallel feature; benchmark stability (kylix-cli)
- **Quality**: ACVP tests, fuzz testing, no_std, constant-time (`subtle`/dudect), zeroization, proptest, clippy clean (`--all-features` and `--no-default-features`)
- **Infrastructure**: Core shared macros (kylix-core), key type wrapper macros, buffer-write API (`_to` variants), dudect CI
- **Security fixes**: Constant-time hypertree verify (`ct_eq`), constant-time polyvec `check_norm` (`Choice`), SHA-512 for SHA2 category 3/5 (FIPS 205 §10.2), FIPS 203 §7.2 ek modulus check in `ml_kem_encaps`/`ml_kem_decaps`

> See `CHANGELOG.md` for full release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| SIMD NTT (WASM) | LOW | - |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| API: Key/Sig Bytes Method | LOW | Consistency | Unify `as_bytes()` vs `to_bytes()` across crates (see note below) |
| SLH-DSA: wots_pk_gen_to / wots_pk_from_sig_to | LOW | Performance | Add `_to` buffer-write variants for `wots_pk_gen` and `wots_pk_from_sig` to eliminate their single Vec return allocation. Low priority since these are called once per WOTS+ operation (not in hot loops). |
| Poly API Consistency | MEDIUM | Ergonomics | ML-KEM uses module functions (`poly_add()`), ML-DSA uses methods (`.add()`). Standardize to methods |
| k_pke Internal Validation | LOW | Defense-in-depth | `k_pke_encrypt`/`k_pke_decrypt` accept `&[u8]` with no length validation; panics on short input via `try_into().unwrap()`. Currently protected by ML-KEM layer validation (PR #132), but direct `pub(crate)` callers are unguarded. |
| ~~ML-DSA: sign.rs Function Splitting~~ | ~~HIGH~~ | ~~Maintainability~~ | Done — extracted `validate_hints`, `apply_hints`, `encode_w1`, `parse_z`, `compute_hints`, `encode_signature` helpers; removed 38 debug `eprintln!` blocks (1289→985 lines) |
| ~~ML-DSA: validate_hints Unit Tests~~ | ~~MEDIUM~~ | ~~Test coverage~~ | Done — added 11 unit tests covering empty/single/multi-poly valid encodings, wrong length, out-of-order positions, duplicates, end > OMEGA, non-monotonic counts, non-zero unused slots, max valid position |
| ~~ML-DSA: Verify w' Computation Style~~ | ~~LOW~~ | ~~Consistency~~ | Done — unified `ml_dsa_verify` to use `.sub()` matching `ml_dsa_verify_expanded` |
| ML-DSA: ct0 Norm Check (FIPS 204 Alg 2 Step 25) | MEDIUM | Correctness | `ml_dsa_sign` does not check `‖ct0‖_∞ ≥ gamma2` as a rejection condition per FIPS 204 Algorithm 2 step 25. Investigate whether this is intentionally omitted or a gap. |
| ML-DSA: Sign Failure Path Zeroization | MEDIUM | Security | `ml_dsa_sign` does not explicitly zeroize `rho_prime`, `s1`, `s2`, `t0`, `s1_hat`, `s2_hat`, `t0_hat` when returning `None` at `MAX_ATTEMPTS`. These types derive `Zeroize` but not `ZeroizeOnDrop`, so secrets may linger on the stack. Add explicit zeroize or derive `ZeroizeOnDrop` for `PolyVecK`/`PolyVecL`. |
| ML-DSA: `ml_dsa_verify` pk Length Check | LOW | Defense-in-depth | `ml_dsa_verify` accesses `pk[0..32]` and `pk[offset..offset+320]` without validating `pk.len()`. Currently safe because all public API callers pass pre-validated `VerificationKey`, but the function accepts `&[u8]` and would panic on short input. Add an early length check matching `expand_verification_key`. |
| ML-DSA: Nonce u16 Overflow at High Iteration Count | LOW | Correctness | In `ml_dsa_sign`, `nonce as u16` truncates for ML-DSA-87 (L=7) when `kappa > 9362` (nonce = kappa\*L+i > 65535). Astronomically unlikely to reach but technically incorrect. Consider using `u32` nonces or lowering `MAX_ATTEMPTS`. Pre-existing issue, not introduced by sign.rs refactor. |
| SLH-DSA: parallel/sequential Sign Dedup | MEDIUM | Code quality | `slh_sign_impl()` has parallel and sequential versions (~90 lines each) that differ only in trait bounds (`Send + Sync`), FORS sign function call, and address mutability semantics. Unification is non-trivial due to Rust's inability to conditionally apply trait bounds. |

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
