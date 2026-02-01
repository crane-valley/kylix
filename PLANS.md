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

> See `CHANGELOG.md` for release history and `BENCHMARKS.md` for performance data.

### Not Started

| Component | Priority | Notes |
|-----------|----------|-------|
| Security Audit | HIGH | External |
| SIMD NTT (WASM) | LOW | - |

### Refactoring Backlog

| Component | Priority | Impact | Notes |
|-----------|----------|--------|-------|
| ~~Lib: Dead Code Audit~~ | ~~MEDIUM~~ | ~~Clarity~~ | ✓ Removed ~112 LOC from kylix-ml-dsa |
| ~~Lib: SLH-DSA Variants~~ | ~~LOW~~ | ~~~600 LOC~~ | ✓ Consolidated with `define_slh_dsa_variant!` macro |
| ~~ML-DSA: AVX2 Barrett~~ | ~~LOW~~ | ~~Performance~~ | ✓ Vectorized Barrett reduction and caddq in `simd/avx2.rs` |
| API: Key/Sig Bytes Method | LOW | Consistency | Unify `as_bytes()` vs `to_bytes()` across crates (see note below) |
| SLH-DSA: no_std test imports | LOW | Test | Add `use alloc::vec;` to test modules (utils.rs, sign.rs) for no_std builds |
| ~~SLH-DSA: slh_sign buffer API~~ | ~~MEDIUM~~ | ~~Performance~~ | ✓ Added `_to` buffer-write variants for all signing functions; `slh_sign_impl` now pre-allocates a single buffer |
| ~~SLH-DSA: HashSuite buffer API~~ | ~~LOW~~ | ~~Performance~~ | ✓ Added `_to` buffer-write variants to HashSuite trait + SHAKE/SHA2 backends; propagated to `wots_chain_to`, `fors_tree_node_to`, `xmss_node_to` and all callers including parallel variants (PR #124) |
| SLH-DSA: wots_pk_gen_to / wots_pk_from_sig_to | LOW | Performance | Add `_to` buffer-write variants for `wots_pk_gen` and `wots_pk_from_sig` to eliminate their single Vec return allocation. Low priority since these are called once per WOTS+ operation (not in hot loops). |
| ~~Core: Modular Arithmetic~~ | ~~HIGH~~ | ~~200 LOC~~ | ✓ Extracted Barrett/Montgomery reduction macros to kylix-core (ML-KEM i16, ML-DSA i32) |
| ~~Core: NTT Abstraction~~ | ~~HIGH~~ | ~~100 LOC~~ | ✓ Extracted `define_ntt_forward!` / `define_ntt_inverse!` macros to kylix-core (ML-KEM i16, ML-DSA i32) |
| ~~Core: SIMD Wrapper Macro~~ | ~~MEDIUM~~ | ~~200 LOC~~ | ✓ Extracted `define_simd_dispatch!` / `define_has_avx2!` macros to kylix-core (~400 LOC net reduction) |
| Poly API Consistency | MEDIUM | Ergonomics | ML-KEM uses module functions (`poly_add()`), ML-DSA uses methods (`.add()`). Standardize to methods |
| ~~ML-KEM/ML-DSA: Clippy Fixes~~ | ~~LOW~~ | ~~Quality~~ | ✓ Replaced `#[allow(dead_code)]` with `#[cfg(test)]` for test-only functions, replaced `manual_div_ceil` with `.div_ceil()`, removed unnecessary lint suppression |
| ~~ML-KEM/ML-DSA: Eliminate intermediate buffers~~ | ~~MEDIUM~~ | ~~Security~~ | ✓ Fixed in PRs #117, #118 (see "Intermediate Buffer Cleanup" section) |

#### Intermediate Buffer Cleanup

**Issue:** Several `from_bytes()` implementations create intermediate stack buffers for sensitive key material. While the final structs implement `ZeroizeOnDrop`, the intermediate buffers are not zeroized, potentially leaving secret material on the stack.

**Problematic Pattern:**
```rust
// Current (creates intermediate buffer)
let mut key = [0u8; SK_SIZE];
key.copy_from_slice(bytes);
Ok(Self { bytes: key })
```

**Recommended Pattern:**
```rust
// Better (writes directly into struct)
let mut result = Self { bytes: [0u8; SK_SIZE] };
result.bytes.copy_from_slice(bytes);
Ok(result)
```

**Affected Files:**

| File | Function | Data Type | Priority |
|------|----------|-----------|----------|
| `kylix-ml-kem/src/types.rs:26-36` | `DecapsulationKey::from_bytes()` | SENSITIVE | HIGH |
| `kylix-ml-dsa/src/types.rs:26-36` | `SigningKey::from_bytes()` | SENSITIVE | HIGH |
| `kylix-ml-kem/src/types.rs:52-62` | `EncapsulationKey::from_bytes()` | Public | LOW |
| `kylix-ml-dsa/src/types.rs:52-62` | `VerificationKey::from_bytes()` | Public | LOW |
| `kylix-ml-kem/src/types.rs:78-88` | `Ciphertext::from_bytes()` | Public | LOW |
| `kylix-ml-dsa/src/types.rs:120-130` | `Signature::from_bytes()` | Public | LOW |

**keygen() Intermediate Buffers:**

| File | Issue | Priority |
|------|-------|----------|
| `kylix-ml-dsa/src/ml_dsa_*.rs:32-44` | `sk_bytes` not zeroized after `SigningKey::from_bytes()` | MEDIUM |
| `kylix-ml-kem/src/ml_kem_*.rs:36-54` | `dk_bytes` not zeroized after `DecapsulationKey::from_bytes()` | MEDIUM |

**Note:** SLH-DSA `types.rs` was already fixed in PR #113 to use the direct-write pattern.

#### API Consistency Note

ML-KEM/ML-DSA use `as_bytes() -> &[u8]`, SLH-DSA uses `to_bytes()` with mixed semantics:
- `SigningKey.to_bytes() -> Zeroizing<Vec<u8>>` (owned, OK)
- `VerificationKey.to_bytes() -> Vec<u8>` (owned, OK)
- `Signature.to_bytes() -> &[u8]` (borrowed, **should be `as_bytes()`** per Rust convention)

Recommended fix: Add `as_bytes()` methods returning `&[u8]` for all types, deprecate inconsistent `to_bytes()` on `Signature`.

#### ~~SLH-DSA Internal Structure Refactoring Plan~~ ✓ Completed in PR #113

**Goal:** Unify SLH-DSA with ML-KEM/ML-DSA by changing internal storage from struct-based to `[u8; SIZE]`.

**Current Structure (SLH-DSA):**
```rust
// types.rs - wrappers around internal structs
pub struct SigningKey(SecretKey<N>);      // Indirect: wraps struct with 4 arrays
pub struct VerificationKey(PublicKey<N>); // Indirect: wraps struct with 2 arrays
pub struct Signature(Vec<u8>);            // Heap-allocated

// sign.rs - internal structs with named fields
pub struct SecretKey<const N: usize> {
    pub sk_seed: [u8; N], pub sk_prf: [u8; N],
    pub pk_seed: [u8; N], pub pk_root: [u8; N],
}
pub struct PublicKey<const N: usize> {
    pub pk_seed: [u8; N], pub pk_root: [u8; N],
}
```

**Target Structure (like ML-KEM/ML-DSA):**
```rust
// types.rs - direct fixed-size array storage
pub struct SigningKey { bytes: [u8; SK_BYTES] }
pub struct VerificationKey { bytes: [u8; PK_BYTES] }
pub struct Signature(Vec<u8>);  // Heap-allocated due to large size (up to 49KB)
```

**Benefits:**
- **Performance:** No heap allocation for keys, better cache locality
- **Security:** Simpler zeroization for keys (single contiguous region)
- **Maintainability:** Consistent API across all three crates
- **Type Safety:** Fixed-size arrays prevent size mismatches for keys

**API Changes (Breaking):**
| Type | Current | New |
|------|---------|-----|
| `SigningKey.to_bytes()` | `Zeroizing<Vec<u8>>` | Removed |
| `SigningKey.as_bytes()` | N/A | `&[u8]` |
| `VerificationKey.to_bytes()` | `Vec<u8>` | Removed |
| `VerificationKey.as_bytes()` | N/A | `&[u8]` |
| `Signature.to_bytes()` | `&[u8]` | Removed |
| `Signature.as_bytes()` | N/A | `&[u8]` |
| `*.from_bytes()` | `Option<Self>` | `Result<Self, Error>` |

**Implementation Steps:**
1. Update `define_slh_dsa_variant!` macro in `types.rs`:
   - Change `SigningKey` to hold `[u8; SK_BYTES]`
   - Change `VerificationKey` to hold `[u8; PK_BYTES]`
   - Keep `Signature` as `Vec<u8>` (up to 49KB, too large for stack)
   - Implement `as_bytes() -> &[u8]` for all types
   - Change `from_bytes()` to return `Result<Self, Error>`
   - Derive `Zeroize + ZeroizeOnDrop` for `SigningKey`

2. Update `sign.rs` internal functions:
   - Keep `SecretKey<N>` / `PublicKey<N>` for internal use (keygen, sign, verify)
   - Add conversion between `[u8; SIZE]` and internal structs
   - Add `write_to()` methods to `SecretKey`/`PublicKey` for direct buffer writes
   - Internal functions retain current signatures:
     - `slh_keygen` returns `(SecretKey<N>, PublicKey<N>)`
     - `slh_sign` accepts `&SecretKey<N>` and returns `Vec<u8>` (large signatures)
     - `slh_verify` accepts `&PublicKey<N>` and `&[u8]`
   - Wrapper types in `types.rs` handle conversion to/from byte arrays

3. Update all variant modules (shake_128f, shake_128s, etc.):
   - Pass correct SIZE constants to macro
   - Ensure SIZE constants match FIPS 205 requirements

4. Update kylix-cli:
   - Replace `to_bytes()` calls with `as_bytes()`
   - Handle `Result` instead of `Option` for `from_bytes()`

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
- [x] Property-based tests (proptest: roundtrip, key/sig sizes, tampering detection)
- [ ] Constant-time formal verification
- [ ] Security audit
