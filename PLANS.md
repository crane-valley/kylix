# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

This roadmap is intentionally scoped for an experimental PoC. The focus is on
performance and implementation quality improvements that a coding agent can
drive directly. Tasks that mainly improve production ecosystem compatibility,
packaging, or audit readiness are deferred unless the project direction changes.

---

## Current Status

- **Latest published release**: `v0.4.5`
- **Workspace version on `main`**: `0.5.0` (unreleased; see `CHANGELOG.md`)

### Completed on `main`

- **Algorithms**: ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA-SHAKE/SHA2 all variants (FIPS 205)
- **Performance**: SIMD (AVX2/NEON) for NTT, basemul, Barrett reduction, pointwise mul; ML-DSA WASM-SIMD128 pointwise mul; ML-DSA expanded verification; SLH-DSA parallel feature; benchmark stability (kylix-cli)
- **Quality**: ACVP tests, fuzz testing, no_std, constant-time (`subtle`/dudect), zeroization, proptest, clippy clean (`--all-features` and `--no-default-features`)
- **Infrastructure**: Core shared macros (kylix-core), key type wrapper macros, buffer-write API (`_to` variants), dudect CI
- **Security fixes**: Constant-time hypertree verify (`ct_eq`), constant-time polyvec `check_norm` (`Choice`), SHA-512 for SHA2 category 3/5 (FIPS 205 §10.2), FIPS 203 §7.2 ek modulus check in `ml_kem_encaps`/`ml_kem_decaps`, `ml_dsa_verify` public-key length check (commit 212c030)
- **API**: Unified `as_bytes() -> &[u8]` across ML-KEM, ML-DSA, and SLH-DSA key and signature types. The ML-DSA return-type change is part of the unreleased 0.5.0 compatibility notes in `CHANGELOG.md`.
- **Refactoring**: ML-DSA sign.rs function splitting (PR #143); checked ML-DSA mask-nonce conversion with an overflow boundary test; unified plain/expanded ML-DSA verification; a single SLH-DSA signing body with feature-specific dispatch; and WOTS+ `wots_pk_gen_to` / `wots_pk_from_sig_to` buffer-write paths

> See `CHANGELOG.md` for full release history and `BENCHMARKS.md` for performance data.

### Near-Term Priorities

| Component | Priority | Notes |
|-----------|----------|-------|
| SHA3/SHAKE SIMD Optimization | HIGH | Keccak permutation AVX2 — SHA3/SHAKE is 40-50% of ML-KEM total time. No Rust PQC lib has this yet (differentiation opportunity). |
| Fuzz Targets for Error/Validation Paths | LOW | Done: ML-KEM `fuzz_encaps`/`fuzz_decaps` and ML-DSA/SLH-DSA `fuzz_verify_bytes` feed attacker-controlled keys, ciphertexts and signatures of any length, with per-target `-max_len` in CI. Remaining: untrusted signing-key bytes for ML-DSA/SLH-DSA signing, and SLH-DSA parameter sets other than SHAKE-128f/SHA2-128f. |
| k_pke Internal Validation | HIGH | Prevent short-input panics in internal encryption/decryption helpers. Good defense-in-depth with limited implementation cost. |
| SIMD NTT (WASM) | LOW | ML-DSA pointwise mul done; NTT not yet WASM-optimized. ML-KEM has no WASM SIMD. |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| Poly API Consistency | LOW | Ergonomics | ML-KEM uses module functions (`poly_add()`), ML-DSA uses methods (`.add()`). Standardize only if the API churn is worth it. |

---

## Optional Verification Work

These items matter if Kylix moves beyond a PoC and starts targeting outside
adoption or production-adjacent use. They are intentionally separated from the
agent-friendly implementation backlog above.

### Constant-time Verification

Dudect-based timing tests in `timing/` directory.
- ML-KEM decaps: CI gate (`timing/dudect-gate.sh`) warns when 4.5 < |max t| <= 10 and fails when |max t| > 10 in a majority of up to 3 runs
- ML-DSA sign: expected variance (rejection sampling)

**Future work:**
- ML-KEM `check_ek_modulus` dudect test (LOW — verify CT property of coefficient scan under release LTO)
- ML-DSA subroutine-level timing tests (NTT, poly ops, secret vector operations)
- SLH-DSA timing tests (LOW — inherently constant-time hash-based design)
- Formal verification (ct-verif / ctgrind) for critical paths
- Secret polynomial arithmetic still returns by value before being wrapped in `Zeroizing` (ML-KEM `PolyVec::from_bytes` of dk_pke, `inner_product`, `matrix_vec_mul`; ML-DSA `mul_vec`, `pointwise_mul`, `Poly::add`), and the public `kem::ml_kem_encaps`/`ml_kem_decaps` return the shared secret as a plain array; write into caller-owned zeroizing destinations where feasible (see docs/adr/0001)
- Other zeroization residuals (see docs/adr/0001 and docs/adr/0002): the `Kem` trait methods return `SharedSecret` by value, so the move can leave an unwiped copy; registers and stack spills are not wiped (the per-lane word in sponge absorb and squeeze, the scratch lanes inside `keccak::f1600`, and the round temporaries and byte-wise digest output of the SLH-DSA in-crate SHA-2 compression); SLH-DSA SHA2 F runs on `sha2::compress256`, whose portable backend (CPUs without SHA-NI, thumbv7em) copies PK.seed, ADRSc and one-time WOTS+ or FORS values into unwiped locals

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
- [x] Dudect CI integration (ML-KEM decaps gate: 1M measurements per bench, valid-vs-invalid and fixed-vs-random ciphertexts, fails at |max t| > 10, warns above 4.5)
- [x] cargo-audit in CI
- [x] `unsafe_op_in_unsafe_fn` denied across workspace (SIMD modules explicitly allowed)
- [x] `clippy::unwrap_used` / `clippy::expect_used` denied across workspace (justified uses annotated)
- [x] Property-based tests (proptest: roundtrip, key/sig sizes, tampering detection)
- [x] CLAUDE.md expansion (SIMD, dudect, CI, crate graph) + docs/ARCHITECTURE.md
- [x] Fuzz targets for error/validation paths (untrusted keys, ciphertexts and signatures of any length)

---

## Deferred Review Findings (2026-09-27)

Found in the 2026-09-27 whole-repository review and left out of the
remediation PRs (#193-#198). Zeroization residuals (Constant-time
Verification, future work) and fuzzing gaps (Near-Term Priorities, fuzz
targets row) are tracked in the sections above, not here.

### API

- Hedged signing and context-string APIs, HashML-DSA and HashSLH-DSA: needs a `Signer` trait change and an ADR
- Hazmat or test-only gating for the doc-hidden internal modules (ml-kem `kem`, ml-dsa `sign`, slh-dsa `sign`)
- `ConstantTimeEq` for `SharedSecret`
- `rand_core` 0.9 `TryCryptoRng` / `OsRng` support
- Unused `Error` variants
- `Poly::conditional_select` uses an inverted argument convention compared with `subtle`
- SLH-DSA: tie `H::N` to the parameter-set `N` at compile time

### Performance

- SLH-DSA hypertree parallelism: the `parallel` feature only parallelizes FORS (1.06-1.39x)
- SHA2 midstate caching for SLH-DSA
- ML-KEM SIMD lane utilization in basemul
- Validate-at-import key types: `from_bytes` checks only the length today, so ML-KEM encaps checks the encapsulation-key coefficients and decaps checks the embedded H(ek) and ek coefficients on every call. Validating keys at import would let these per-call checks be dropped

### CI

- Miri and sanitizers for the SIMD code
- Disassembly check for division instructions on secret paths
- Root cargo commands run without `--locked`
- `timing/Cargo.lock` is lockfile v4, which cargo 1.75 cannot read, and the MSRV job does not cover `timing/`
- The dudect gate cannot reliably catch very small leaks
- `timing/dudect-gate.sh` shell hardening (P3): `mktemp` / `trap` ordering

### Tests

- Test for the ek modulus check on the decaps path
- ML-DSA ACVP sigVer module duplication
- `deterministic_fixtures` runs 0 tests with only f-variant features enabled
- Redundant per-item aarch64 cfgs inside the NEON modules
- AVX2 parity tests return early on hosts without AVX2

### Cleanup

- Remaining `#[allow(dead_code)]` in kylix-ml-kem (`hash.rs` squeeze, `params` constants, `poly_add_assign`)
- Pre-existing non-ASCII characters in ml-kem `encode.rs` / `polyvec.rs` comments
