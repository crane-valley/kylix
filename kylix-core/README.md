# kylix-core

Core traits, error types, and macros for the [Kylix](https://github.com/crane-valley/kylix) post-quantum cryptography library.

This crate is an internal building block — most users should depend on [`kylix-pqc`](https://crates.io/crates/kylix-pqc) or individual algorithm crates instead.

## Contents

### Traits

- **`Kem`** — Key Encapsulation Mechanism (keygen, encaps, decaps). Used by `kylix-ml-kem`.
- **`Signer`** — Digital Signature (keygen, sign, verify). Used by `kylix-ml-dsa` and `kylix-slh-dsa`.

### Error Types

- **`Error`** — Unified error type (invalid lengths, verification failure, decapsulation failure, etc.)
- **`Result<T>`** — Alias for `core::result::Result<T, Error>`

### Macros

Compile-time code generation for lattice-based cryptography:

| Macro | Purpose |
|-------|---------|
| `define_barrett_reduce!` | Barrett modular reduction |
| `define_montgomery_reduce!` | Montgomery reduction |
| `define_montgomery_mul!` | Montgomery multiplication |
| `define_caddq!` | Constant-time conditional add q |
| `define_freeze!` | Canonical reduction to [0, q-1] |
| `define_ntt_forward!` | Cooley-Tukey forward NTT |
| `define_ntt_inverse!` | Gentleman-Sande inverse NTT |
| `define_simd_dispatch!` | Multi-platform SIMD dispatch (AVX2/NEON/WASM) |
| `define_has_avx2!` | Runtime SIMD feature detection |

### Re-exports

- `zeroize::{Zeroize, ZeroizeOnDrop}` — Secure memory erasure
- `subtle` — Constant-time comparison primitives

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | Yes | Enables `thiserror` for `std::error::Error` impl |

### no_std

```toml
kylix-core = { version = "0.4", default-features = false }
```

## License

MIT
