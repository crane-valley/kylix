# Kylix Architecture

Kylix is a pure-Rust implementation of the NIST post-quantum standards
ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). The workspace is
distributed as source from this repository (all packages are
`publish = false`). MSRV: 1.75.

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

Secret-dependent selections and comparisons use `subtle` (`Choice`,
`ConditionallySelectable`, `ct_eq`) or mask arithmetic, and checks over
secret data accumulate a result instead of returning early:

```rust
// Accumulate results via bitwise operations — no early returns
let mut pass = Choice::from(1u8);
for p in &self.polys {
    pass &= p.check_norm_ct(bound);
}
bool::from(pass)
```

**Protected operations**: norm checking, hypertree verification, implicit
rejection (ML-KEM decapsulation), and ML-KEM compression and `ByteDecode12`,
which use a multiply-shift and a masked subtraction instead of division by q
(hardware division has operand-dependent latency at opt-level 0 and `z`).

This is a best-effort property of the source code. It is not formally
verified, and a compiler or target can still introduce variable-time
instructions. ML-DSA signing uses rejection sampling, so its running time
varies with the number of attempts by design. SLH-DSA control flow depends
only on public values (the message digest selects tree and leaf indices), and
SLH-DSA has no timing tests.

**Timing checks**: `timing/` holds dudect-bencher harnesses. The CI gate
covers ML-KEM-768 decapsulation only, with two benches (valid vs invalid
ciphertext, fixed vs random ciphertext) of 1M measurements each. A bench
whose |max t| exceeds 10 is rerun, and the job fails only if a majority of up
to three runs exceed 10; 4.5 < |max t| <= 10 is a warning. The gate catches
gross leaks, such as a branch on the implicit-rejection comparison (|t| near
1000 in a deliberate test), but a shared, noisy runner cannot reliably detect
small leaks. It says nothing about ML-DSA, SLH-DSA, other ML-KEM operations,
or builds other than the x86_64 release build it runs. The `ml_dsa` harness
is for manual runs only.

### Zeroization

Secret key types (signing keys, decapsulation keys) and shared secrets
implement `Zeroize + ZeroizeOnDrop`. Signing, key generation and
decapsulation hold secret intermediates such as polynomial vectors, seeds and
nonces in `Zeroizing` wrappers where the code controls the storage.

Coverage of intermediates is best-effort, not complete. Values returned by
value before they are wrapped, copies left behind by moves, register and
stack spills, and hash-function internal state can leave unwiped copies. The
design for secret-absorbing hash state and the known residuals are recorded
in `docs/adr/0001-wipe-secret-absorbing-hash-state.md` and in `PLANS.md`.

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
| `simd` | Yes | ML-KEM and ML-DSA SIMD backends (forwards to the members' `simd`) |
| `ml-kem` | Yes | All ML-KEM variants |
| `ml-dsa` | Yes | All ML-DSA variants |
| `slh-dsa` | Yes | SLH-DSA SHAKE variants |
| `slh-dsa-sha2` | No | SLH-DSA SHA2 variants; works on its own or together with `slh-dsa` |

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
| ACVP compliance | Custom (serde_json) | NIST vectors for every parameter set; see below |
| Interoperability | OpenSSL 3.6.0 outputs pinned in tests | SLH-DSA signing for all 12 sets; ML-DSA KeyGen boundary seeds |
| Property-based | proptest | Roundtrip, determinism, size validation |
| Constant-time | dudect-bencher | ML-KEM-768 decaps (CI gate); ML-DSA sign harness for manual runs |
| Fuzz testing | cargo-fuzz (libFuzzer) | Keygen, sign, verify, roundtrip, and untrusted keys, ciphertexts and signatures |
| Unit tests | Built-in | Reduction, NTT, encoding, parameter validation |
| Dependency audit | cargo-audit | CI integration |

ACVP coverage:

- ML-KEM: keyGen, encapsulation and decapsulation, and the
  encapsulation-key and decapsulation-key check groups.
- ML-DSA: keyGen and every sigGen and sigVer group (internal, external pure,
  external pre-hash, external mu).
- SLH-DSA: keyGen and every sigVer group (internal, external pure, external
  pre-hash) for all 12 parameter sets. The repository has no SLH-DSA sigGen
  vectors, so signing is checked against OpenSSL instead.

ACVP test vectors (1.4-30 MB) are kept in the Git repository and omitted from
ad-hoc Cargo package archives. Tests skip when the vectors are missing unless
`KYLIX_REQUIRE_ACVP=1` is set, as it is in CI.

## Build Profiles

The dev profile optimizes the crypto crates and their hash dependencies
because tests are otherwise slow (SLH-DSA is 10-15x slower at opt-level 0).
It is not needed for zeroization, which `zeroize` performs with volatile
writes at every opt-level. Cargo package overrides take exact package names
(`"*"` matches only non-workspace dependencies), so each package is listed
by name:

```toml
# Dev/test: per-package overrides, one entry per package
[profile.dev.package.kylix-core]
opt-level = 2
[profile.dev.package.kylix-ml-kem]
opt-level = 2
# ... likewise kylix-ml-dsa, kylix-slh-dsa, sha3, keccak, digest, sha2, hmac, subtle

# Release: maximum optimization
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

## Algorithm Notes

### ML-KEM (FIPS 203)

- Parameter sets: 512 (Category 1), 768 (Category 3), 1024 (Category 5)
- FIPS 203 section 7.2 modulus check on the encapsulation key in encaps and
  decaps; section 7.3 hash check of the decapsulation key before decaps
- Implicit rejection: an invalid ciphertext yields a pseudorandom shared secret

### ML-DSA (FIPS 204)

- Parameter sets: 44 (Category 2), 65 (Category 3), 87 (Category 5)
- Pure signing with an empty context; hedged signing, non-empty contexts and
  HashML-DSA are not exposed
- WASM-SIMD128 is implemented for pointwise multiplication only

### SLH-DSA (FIPS 205)

- Stateless hash-based signatures, no lattice arithmetic
- Two hash families: SHAKE (default) and SHA2 (facade feature `slh-dsa-sha2`;
  per-crate features `slh-dsa-sha2-*`)
- Two speed tiers: f (fast signing, larger signatures) and s (small signatures)
- The `parallel` feature (Rayon) parallelizes FORS signing only

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
