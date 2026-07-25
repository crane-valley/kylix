# CLAUDE.md

- Source code, comments, logs, error messages: English
- PR titles, summaries, and comments: English
- Create feature branch -> commit -> push -> PR (merge is done by humans)

## CI Notes

- CI uses `-Dwarnings` so all warnings are treated as errors
- For WIP modules, add `#![allow(dead_code)]` at module top
- Doc comments: `[X]` is interpreted as a link reference by rustdoc; escape as `\[X\]`

## Code Quality Rules

Before committing or creating a PR, always run:
1. `cargo fmt --all` - Format all code
2. `cargo clippy --all-targets --all-features -- -D warnings` - Check for lints
3. `cargo clippy --all-targets --no-default-features -- -D warnings` - Check for lints (no default features)
4. `cargo test --workspace --all-features` - Run all tests

Note: CLI-related tests are in the separate [kylix-cli repository](https://github.com/crane-valley/kylix-cli).

During development, run `cargo fmt --all` frequently (for example, after each edit) to keep formatting consistent and get fast feedback.

## Security: Handling Sensitive Data

When working with secret keys, seeds, or other sensitive cryptographic material:

**Avoid intermediate buffers** - Write directly into the destination struct to prevent sensitive data from lingering on the stack.

```rust
// BAD: Creates intermediate buffer that may not be zeroized
let mut temp = [0u8; SIZE];
temp.copy_from_slice(bytes);
let result = Struct { field: temp };  // temp copied, original stays on stack

// GOOD: Write directly into struct
let mut result = Struct { field: [0u8; SIZE] };
result.field.copy_from_slice(bytes);  // No intermediate buffer
```

For types that implement `from_bytes()` for secret keys:
- Initialize the struct with zeroed arrays first
- Copy data directly into struct fields
- Avoid `try_into()` for secret data (creates intermediate arrays due to Copy trait)

All sensitive key types must implement `Zeroize` and `ZeroizeOnDrop` to ensure automatic cleanup.

## Release

- Main crate is `kylix-pqc` (not `kylix` - that name was taken on crates.io)
- Create a GitHub Release with tag `vX.Y.Z` to auto-publish to crates.io
- Ensure `Cargo.toml` version matches the tag before release
- CLI is in a separate repository: [crane-valley/kylix-cli](https://github.com/crane-valley/kylix-cli)

### Adding a New Crate

When adding a new crate to the workspace:

1. **Update `.github/workflows/publish.yml`**: Add a publish step for the new crate in the correct dependency order (before crates that depend on it)
2. **Exclude large files**: crates.io has a 10MB upload limit. Add `exclude` in `Cargo.toml` to exclude:
   - ACVP test vectors (`tests/acvp/`)
   - Fuzz corpora
   - Other files not needed by library users

   Example:
   ```toml
   [package]
   exclude = ["tests/acvp/"]
   ```

3. **Verify package contents**: Run `cargo package --list -p <crate>` to confirm large files are excluded
4. **Gate excluded tests**: If tests depend on excluded files, add skip logic so tests pass when running from crates.io tarball

## SIMD Development

### Dispatch Pattern (kylix-core/src/simd.rs)

Runtime detection with compile-time fast paths:
- AVX2: `#[target_feature(enable = "avx2")]` + `is_x86_feature_detected!`
- NEON: always available on aarch64 (const true)
- WASM-SIMD128: feature-gated (`core::arch::wasm32` intrinsics)
- Scalar fallback: no_std compatible

Three dispatch flavors (macros in kylix-core):
- Pattern A: avx2 + neon + scalar
- Pattern B: avx2 + neon + wasm + scalar (used by ML-DSA pointwise)
- Pattern C: avx2-only + scalar

### Adding SIMD for a new operation

1. Implement scalar version first (correctness baseline)
2. Add AVX2 backend in `{crate}/src/simd/avx2.rs`
3. Add NEON backend in `{crate}/src/simd/neon.rs`
4. Wire dispatch via kylix-core macros
5. Test both paths: `cargo test --all-features` (SIMD) AND `cargo test --no-default-features` (scalar)

## Constant-Time Testing

- dudect-based timing tests in `timing/` directory (excluded from workspace)
- Run: `cargo run --release -p kylix-timing --bin ml_kem` (must be release for meaningful timing)
- CI threshold: A test passes if `dudect` reports `|max t| <= 4.5`. A result of `|max t| > 4.5` is considered inconclusive if fewer than 0.5 million measurements were taken; otherwise, it is a failure.
- All secret-dependent branches must use `subtle::Choice` / `subtle::ct_eq`
- NEVER use `if` / `match` / `==` on secret data -- use `subtle` crate operations

## Cross-Platform CI

- ci.yml: fast PR checks (fmt, clippy, audit, test on Ubuntu stable, MSRV 1.75, no_std, dudect)
- ci-full.yml: on push to main -- full matrix (Ubuntu, macOS, Windows, ARM64 with SIMD-specific tests, codecov)

## Workspace Crate Graph

```
kylix-core (shared: NTT macros, SIMD dispatch, Barrett reduction, zeroize/subtle re-exports)
  |
  +-- kylix-ml-kem  (FIPS 203: ML-KEM-512/768/1024)
  +-- kylix-ml-dsa  (FIPS 204: ML-DSA-44/65/87)
  +-- kylix-slh-dsa (FIPS 205: SLH-DSA all SHAKE/SHA2 variants)
  |
  +-- kylix-pqc (re-export facade, published as kylix-pqc on crates.io)
```

## Performance Notes

- Dev/test profiles use opt-level=2 for crypto crates (SLH-DSA is 10-15x slower at opt-level=0)
- Release: LTO + codegen-units=1 + panic=abort
- Benchmark via kylix-cli repo: `cargo bench -p kylix-bench`
