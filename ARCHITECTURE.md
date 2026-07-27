# Kylix Architecture

## Crate Dependency Graph

```
kylix-pqc (umbrella crate)
├── kylix-core         (traits, errors, macros)
├── kylix-ml-kem       (FIPS 203 — lattice KEM)
├── kylix-ml-dsa       (FIPS 204 — lattice signatures)
└── kylix-slh-dsa      (FIPS 205 — hash-based signatures)
```

Each algorithm crate depends on `kylix-core` for shared infrastructure. The umbrella crate `kylix-pqc` re-exports all algorithms behind feature flags.

```
kylix-core provides:
├── Kem trait          → used by kylix-ml-kem
├── Signer trait       → used by kylix-ml-dsa, kylix-slh-dsa
├── Error / Result     → used by all
├── Reduction macros   → used by kylix-ml-kem (i16/q=3329), kylix-ml-dsa (i32/q=8380417)
├── NTT macros         → used by kylix-ml-kem, kylix-ml-dsa
└── SIMD dispatch      → used by kylix-ml-kem, kylix-ml-dsa
```

## Workspace Layout

| Path | Package | Notes |
|------|---------|-------|
| `kylix/` | `kylix-pqc` | Facade crate |
| `kylix-core/` | `kylix-core` | Shared traits, errors, reduction/NTT/SIMD macros |
| `kylix-ml-kem/` | `kylix-ml-kem` | ML-KEM implementation crate |
| `kylix-ml-dsa/` | `kylix-ml-dsa` | ML-DSA implementation crate |
| `kylix-slh-dsa/` | `kylix-slh-dsa` | SLH-DSA implementation crate |
| `timing/` | `kylix-timing` | Dudect-based timing checks, excluded from the default workspace |
| `{crate}/fuzz/` | cargo-fuzz targets | Per-crate fuzz harnesses, excluded from the default workspace |

## Module Layout

Every algorithm crate shares a small common core (`lib.rs`, per-variant
wrapper modules, `types.rs`, `params.rs`, and `hash.rs`). Beyond that the
layout follows the algorithm family, so the lattice crates and SLH-DSA differ.

The lattice crates (ML-KEM, ML-DSA) are built around polynomial arithmetic:

```
kylix-ml-kem/src/            kylix-ml-dsa/src/
├── lib.rs                   ├── lib.rs
├── {variant}.rs             ├── {variant}.rs      # ml_dsa_65.rs, ...
├── types.rs                 ├── types.rs
├── params.rs                ├── params.rs
├── poly.rs                  ├── poly.rs
├── polyvec.rs               ├── polyvec.rs
├── ntt.rs                   ├── ntt.rs
├── reduce.rs                ├── reduce.rs
├── sample.rs                ├── sample.rs
├── hash.rs                  ├── hash.rs
├── encode.rs                ├── packing.rs        # bit-packing (no encode.rs)
├── matrix.rs                ├── rounding.rs       # Power2Round / Decompose
├── k_pke.rs                 ├── sign.rs
├── kem.rs                   └── simd/
└── simd/                        ├── avx2.rs
    ├── avx2.rs                  ├── neon.rs
    └── neon.rs                  └── wasm.rs       # ML-DSA only
```

`ntt.rs` and `reduce.rs` are generated via the kylix-core macros.

SLH-DSA is hash-based and has no polynomial layer, so its modules mirror the
FIPS 205 construction instead:

```
kylix-slh-dsa/src/
├── lib.rs
├── {variant}.rs        # slh_dsa_shake_128f.rs, slh_dsa_sha2_256s.rs, ...
├── types.rs
├── params.rs
├── sign.rs             # slh_keygen / slh_sign / slh_verify
├── wots.rs             # WOTS+ one-time signatures
├── fors.rs             # FORS few-time signatures
├── xmss.rs             # XMSS subtrees
├── hypertree.rs        # Hypertree (HT) over XMSS layers
├── address.rs          # ADRS structure
├── hash.rs             # HashSuite trait
├── hash_shake.rs       # SHAKE instantiation
├── hash_sha2.rs        # SHA2 instantiation
├── utils.rs            # base_2b, WOTS+ checksum
└── parallel.rs         # rayon FORS signing (feature = "parallel")
```

No SLH-DSA SIMD module exists; its speedup path is the `parallel` feature.

## SIMD Optimization

### Dispatch Mechanism

SIMD is implemented via `define_simd_dispatch!` from kylix-core:

```rust
kylix_core::define_simd_dispatch! {
    pub fn ntt(poly: &mut Poly) -> bool;
    avx2: avx2::ntt_avx2(&mut poly.coeffs),
    neon: neon::ntt_neon(&mut poly.coeffs)
}
```

The generated function returns `bool` indicating whether SIMD was used. Scalar fallback is always available.

### Platform Detection

| Platform | Detection | Method |
|----------|-----------|--------|
| x86-64 AVX2 | Runtime | `is_x86_feature_detected!("avx2")` (std) or compile-time flag |
| AArch64 NEON | Compile-time | Always available on AArch64 |
| WASM-SIMD128 | Compile-time | `cfg!(target_feature = "simd128")` |

### Parallelism by Coefficient Width

| Crate | Coefficient | Modulus | AVX2 (256-bit) | NEON (128-bit) | WASM (128-bit) |
|-------|------------|---------|----------------|----------------|----------------|
| ML-KEM | `i16` | q = 3329 | 16 parallel | 8 parallel | — |
| ML-DSA | `i32` | q = 8380417 | 8 parallel | 4 parallel | 4 parallel |

### Optimized Operations

- **NTT forward/inverse**: Cooley-Tukey butterflies with Montgomery multiplication
- **Basemul / Pointwise mul**: Polynomial multiplication in NTT domain
- **Barrett reduction**: Division-free modular reduction
- **Montgomery reduction**: Efficient modular arithmetic for NTT domain

## Security Design

### Constant-Time Operations

Critical paths avoid data-dependent branching using `subtle::Choice`:

```rust
// Accumulate results via bitwise operations — no early returns
let mut pass = Choice::from(1u8);
for p in &self.polys {
    pass &= p.check_norm_ct(bound);
}
bool::from(pass)
```

**Protected operations**: norm checking, hypertree verification, implicit rejection (ML-KEM decapsulation).

**Verification**: Dudect-based timing tests in `timing/` directory with CI regression detection.

### Zeroization

All secret material implements `Zeroize + ZeroizeOnDrop`:
- Signing keys, decapsulation keys, shared secrets
- Intermediate buffers (polynomial vectors, nonces, masking values)

Workspace dev profile sets `opt-level = 2` for crypto crates to ensure zeroization works correctly even in debug builds.

### Input Validation

- `from_bytes()` validates length on all key/signature types
- ML-KEM: FIPS 203 §7.2 encapsulation key modulus check
- ML-KEM: Implicit rejection — invalid ciphertexts produce pseudorandom secrets
- ML-DSA: Hint encoding validation, signature norm bounds

## Key Type System

Each algorithm crate uses macros to generate consistent key types:

```
define_kem_types!  → DecapsulationKey, EncapsulationKey, Ciphertext, SharedSecret
define_dsa_types!  → SigningKey, VerificationKey, Signature, ExpandedVerificationKey
define_slh_dsa_variant! → SigningKey, VerificationKey, Signature
```

All types provide:
- `from_bytes(&[u8]) -> Result<Self>` with length validation
- `as_bytes() -> &[u8]` for serialization
- Fixed-size arrays (stack-allocated) except SLH-DSA `Signature` (heap, up to 49 KB)

## Feature Flag Design

### Umbrella Crate (kylix-pqc)

| Flag | Default | Effect |
|------|---------|--------|
| `std` | Yes | Standard library support |
| `ml-kem` | Yes | All ML-KEM variants |
| `ml-dsa` | Yes | All ML-DSA variants |
| `slh-dsa` | Yes | SLH-DSA SHAKE variants |
| `slh-dsa-sha2` | No | SLH-DSA SHA2 variants |

### Per-Crate Flags

Each algorithm crate supports:
- `std` — Standard library (default on)
- `simd` — SIMD optimizations (ML-KEM, ML-DSA; default on)
- Per-variant flags — Compile only needed parameter sets
- `parallel` — Multi-threaded signing (SLH-DSA only, requires `std`)

For SLH-DSA specifically, the facade crate exposes `slh-dsa-sha2`, while the
algorithm crate exposes per-variant SHA2 features such as
`slh-dsa-sha2-128f` and `slh-dsa-sha2-256s`.

### no_std

All crates support `no_std` with `alloc`. Disable default features and select variants:

```toml
kylix-ml-kem = { git = "https://github.com/crane-valley/kylix.git", default-features = false, features = ["ml-kem-768"] }
```

## Testing Strategy

| Layer | Framework | Coverage |
|-------|-----------|----------|
| ACVP compliance | Custom (serde_json) | NIST official test vectors for all algorithms |
| Property-based | proptest | Roundtrip, determinism, size validation |
| Constant-time | dudect-bencher | ML-KEM decaps, ML-DSA sign timing |
| Fuzz testing | cargo-fuzz (libFuzzer) | Keygen, sign, verify, roundtrip per algorithm |
| Unit tests | Built-in | Reduction, NTT, encoding, parameter validation |
| Dependency audit | cargo-audit | CI integration |

ACVP test vectors (1.4-30 MB) are kept in the Git repository and omitted from
ad-hoc Cargo package archives.

## Build Profiles

```toml
# Dev: crypto crates optimized even in debug builds
[profile.dev.package.kylix-*]
opt-level = 2

# Release: maximum optimization
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

## Performance Summary

### ML-KEM-768 (Intel i5-13500, AVX2)

| Library | Encaps |
|---------|--------|
| libcrux (verified + ASM) | ~11 µs |
| **Kylix** | **~23 µs** |
| RustCrypto ml-kem | ~33 µs |
| pqcrypto (C FFI) | ~42 µs |

### Bottleneck Analysis

- **ML-KEM/ML-DSA**: SHA3/SHAKE is 40-50% of total time. NTT/basemul already SIMD-optimized. AVX2 Keccak permutation is the primary remaining optimization opportunity.
- **SLH-DSA**: Inherently hash-intensive (ms-scale). `parallel` feature helps signing via multi-threaded FORS computation.
