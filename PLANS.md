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

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| CLI Bench Compare CI | MEDIUM | Test OpenSSL/liboqs detection on Linux/macOS |
| SLH-DSA SHA2 Variants | LOW | FIPS 205 |
| SIMD NTT (WASM) | LOW | - |
| Property-based Tests | LOW | proptest |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| CLI: Algorithm Dispatch | HIGH | ~300 LOC | Extract 12-way match blocks into trait/factory pattern |
| Lib: Key Type Wrappers | HIGH | ~400 LOC | Consolidate `DecapsulationKey`, `SigningKey` etc. with generics/macros |
| CLI: Long Functions | MEDIUM | Readability | Break up `cmd_sign` (135L), `cmd_verify` (127L), `cmd_keygen` (94L) |
| CLI: Constant Table | MEDIUM | ~40 LOC | Replace 42 lines of size constants with `AlgorithmInfo` lookup |
| Lib: Dead Code Audit | MEDIUM | Clarity | Audit `#[allow(dead_code)]` in kylix-ml-dsa (9 modules) |
| Lib: SLH-DSA Variants | LOW | ~600 LOC | Consolidate 6 variant files with macro generation |
| CLI: Unused `is_dsa()` | LOW | 5 LOC | Remove or use the method |
| CLI: Error Patterns | LOW | Consistency | Standardize `map_err` vs `ok_or_else` usage |
| CLI: OpenSSL Dedup | LOW | ~50 LOC | Extract common logic from KEM/SIG benchmark functions |
| CLI: Speedup Helper | LOW | ~20 LOC | Extract speedup calculation into shared function |
| CLI: liboqs Parsing | LOW | Robustness | Parse column headers instead of hardcoded indices |
| CLI: Test Message | LOW | Clarity | Define module-level constant for test phrases |
| CLI: wolfSSL Support | LOW | Feature | Add wolfSSL as external benchmark tool |

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

### CLI Algorithm Dispatch (HIGH)

`main.rs` contains 5+ identical 12-way match blocks for algorithm dispatch:
- `cmd_keygen` (lines 391-452)
- `cmd_sign` (lines 737-801)
- `cmd_verify` (lines 875-939)

**Solution:** Trait-based dispatch or factory pattern with `AlgorithmInfo` table.

### Key Type Wrappers (HIGH)

12+ files contain nearly identical struct implementations:
```rust
pub struct DecapsulationKey { bytes: [u8; SIZE] }
impl DecapsulationKey {
    pub fn from_bytes(...) -> Result<Self> { ... }
    pub fn as_bytes(&self) -> &[u8] { ... }
}
```

**Solution:** Generic `KeyWrapper<const N: usize>` or macro generation.

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
- [ ] Property-based tests
- [ ] Security audit
