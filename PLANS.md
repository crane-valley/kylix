# Kylix Development Roadmap

Pure Rust, high-performance implementation of NIST PQC standards (FIPS 203/204/205).

---

## Current Status (v0.4.2)

### Completed

- ML-KEM-512/768/1024 (FIPS 203) with SIMD (AVX2/NEON) optimizations for NTT, basemul, and Barrett reduction
- ML-DSA-44/65/87 (FIPS 204) with SIMD (AVX2/NEON) and expanded verification
- SLH-DSA-SHAKE all variants (FIPS 205) with parallel feature
- NIST ACVP tests, fuzz testing, CLI, no_std, constant-time, zeroization
- CLI bench feature extraction: benchmark code moved to optional `bench` feature in `src/bench.rs`
- CLI binary distribution: cargo-dist for GitHub Releases with shell/powershell installers
- CLI security improvements: secret key file permissions (Unix 0o600), consistent zeroization, atomic file writes

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| cargo-audit in CI | MEDIUM | Add automated dependency vulnerability scanning to CI |
| CLI Bench Compare CI | MEDIUM | Test OpenSSL/liboqs detection on Linux/macOS |
| SLH-DSA SHA2 Variants | LOW | FIPS 205 |
| SIMD NTT (WASM) | LOW | - |
| Property-based Tests | LOW | proptest |
| ~~Constant-time Verification~~ | ~~LOW~~ | ✓ Added dudect tests in `timing/` |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| ~~CLI: Constant Table~~ | ~~MEDIUM~~ | ~~~40 LOC~~ | ✓ Replaced with `AlgorithmInfo` lookup |
| ~~Lib: Key Type Wrappers~~ | ~~HIGH~~ | ~~265 LOC~~ | ✓ Added `define_kem_types!` / `define_dsa_types!` macros |
| CLI: Long Functions | MEDIUM | Readability | Break up `cmd_sign` (135L), `cmd_verify` (127L), `cmd_keygen` (94L) |
| Lib: Dead Code Audit | MEDIUM | Clarity | Audit `#[allow(dead_code)]` in kylix-ml-dsa (9 modules) |
| Lib: SLH-DSA Variants | LOW | ~600 LOC | Consolidate 6 variant files with macro generation |
| CLI: Unused `is_dsa()` | LOW | 5 LOC | Remove or use the method |
| CLI: Error Patterns | LOW | Consistency | Standardize `map_err` vs `ok_or_else` usage |
| CLI: OpenSSL Dedup | LOW | ~50 LOC | Extract common logic from KEM/SIG benchmark functions |
| CLI: Speedup Helper | LOW | ~20 LOC | Extract speedup calculation into shared function |
| CLI: liboqs Parsing | LOW | Robustness | Parse column headers instead of hardcoded indices |
| CLI: Test Message | LOW | Clarity | Define module-level constant for test phrases |
| CLI: wolfSSL Support | LOW | Feature | Add wolfSSL as external benchmark tool |
| ML-DSA: AVX2 Barrett | LOW | Performance | Vectorized Barrett reduction TODO in `simd/avx2.rs` |

### Pending: CLI Bench Compare CI Testing

Add CI workflow to test `kylix bench --compare` with external tools:

- **Linux**: Install liboqs via apt/build from source, test detection
- **macOS**: Install liboqs via Homebrew, test detection
- **OpenSSL 3.5+**: Test PQC provider detection when available

Goal: Verify cross-platform tool detection works correctly.

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
- Add SLH-DSA timing tests (slow due to hash-based signatures)
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

## Refactoring Notes

### CLI Algorithm Dispatch (PARTIAL ✓)

Introduced `AlgorithmInfo` metadata struct and consolidated algorithm detection:
- Added `AlgorithmInfo` with `pub_key_size`, `sec_key_size`, `output_size`, `pub_label`, `sec_label`
- Added `Algorithm::info()` const method for metadata lookup
- Added `Algorithm::detect_kem_from_pub_key()`, `detect_kem_from_sec_key()`, `detect_dsa_from_signing_key()`, `detect_dsa_from_verification_key()` methods
- Removed 42 lines of size constants
- Simplified `cmd_info()` to use loop-based display
- Simplified `cmd_keygen()`, `cmd_sign()`, `cmd_verify()` to use `AlgorithmInfo`

**Remaining**: The 12-way match blocks in keygen/sign/verify remain due to heterogeneous types (`as_bytes()` vs `to_bytes()`, `Result` vs `Option`). Macro-based generation would not significantly improve maintainability.

### Key Type Wrappers (✓ COMPLETE)

Added `define_kem_types!` and `define_dsa_types!` macros to consolidate key type definitions:
- `kylix-ml-kem/src/types.rs`: Generates `DecapsulationKey`, `EncapsulationKey`, `Ciphertext`, `SharedSecret`
- `kylix-ml-dsa/src/types.rs`: Generates `SigningKey`, `VerificationKey`, `Signature`, `ExpandedVerificationKey`
- SLH-DSA not changed (uses newtype pattern wrapping internal types)
- Net reduction: ~265 lines of code

### SLH-DSA Variants (LOW)

6 variant files (`slh_dsa_shake_128s.rs` through `256f.rs`) share ~95% identical code.

**Solution:** Parameterized module or `macro_rules!` generation.

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
- [x] Dudect timing tests (ML-KEM passes, ML-DSA expected variance due to rejection sampling)
- [ ] cargo-audit in CI
- [ ] Property-based tests
- [ ] Constant-time formal verification
- [ ] Security audit
