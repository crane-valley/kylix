# CLAUDE.md

- Source code, comments, logs, error messages: English
- PR titles, summaries, and comments: English
- Create feature branch -> commit -> push -> PR

## CI Notes

- CI uses `-Dwarnings` so all warnings are treated as errors
- CI sets `KYLIX_REQUIRE_ACVP=1`, so a missing `tests/acvp/` directory fails the ACVP tests instead of skipping them (a missing file inside an existing directory always fails)
- Doc comments: `[X]` is interpreted as a link reference by rustdoc; escape as `\[X\]`

## Code Quality Rules

Before committing or creating a PR, always run:
1. `cargo fmt --all` - Format all code
2. `cargo clippy --all-targets --all-features -- -D warnings` - Check for lints
3. `cargo clippy --all-targets --no-default-features -- -D warnings` - Check for lints (no default features)
4. `cargo test --workspace --all-features` - Run all tests

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

## Distribution

- This workspace is source-only and consumed directly from this repository
- Keep every workspace package `publish = false`
- Do not add crates.io publishing workflows or GitHub Release automation
- CLI is in a separate repository: [crane-valley/kylix-cli](https://github.com/crane-valley/kylix-cli)

### Adding a New Crate

When adding a new crate to the workspace:

1. **Disable publication**: Set `publish = false` in the crate's `[package]` table
2. **Keep source archives focused**: Add `exclude` in `Cargo.toml` for:
   - ACVP test vectors (`tests/acvp/`)
   - Fuzz corpora
   - Other large files not needed by library users

   Example:
   ```toml
   [package]
   exclude = ["tests/acvp/"]
   ```

3. **Verify package contents**: Run `cargo package --list -p <crate>` to confirm large files are excluded
4. **Gate excluded tests**: If tests depend on excluded files, add skip logic for partial source archives

## SIMD Development

### Dispatch Pattern (kylix-core/src/simd.rs)

Runtime detection with compile-time fast paths:
- AVX2: `#[target_feature(enable = "avx2")]` + `is_x86_feature_detected!` (with `std`; without `std`, only when compiled with the `avx2` target feature)
- NEON: only on aarch64 targets compiled with the `neon` target feature (compile-time check); other aarch64 targets such as `aarch64-unknown-none-softfloat` use the scalar fallback
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
- Run: `cargo run --release --manifest-path timing/Cargo.toml --bin ml_kem` (must be release for meaningful timing)
- CI gate: `timing/dudect-gate.sh` runs the ML-KEM benches (1M measurements each). A bench with `|max t| > 10` (dudect's own failure level) is rerun and fails the job only if a majority of up to three runs exceed 10, since one noisy shared-runner run can; `4.5 < |max t| <= 10` is a warning. A crashed or incomplete run, a missing or unparsable result, or a failed threshold comparison also fails.
- All secret-dependent branches must use `subtle::Choice` / `subtle::ct_eq`
- NEVER use `if` / `match` / `==` on secret data -- use `subtle` crate operations

## Cross-Platform CI

- ci.yml: fast PR checks (fmt, clippy, audit, test on Ubuntu stable, tests at opt-level 0 and z, MSRV 1.75, no_std builds for thumbv7em and aarch64 softfloat, wasm32 SIMD128 check, dudect)
- ci-full.yml: on push to main -- full matrix (Ubuntu, macOS, Windows, ARM64 NEON, codecov)
- Actions are pinned by commit SHA with a version comment; Dependabot updates them

## Workspace Crate Graph

```
kylix-core (shared: NTT macros, SIMD dispatch, Barrett reduction, zeroize re-exports)
  |
  +-- kylix-ml-kem  (FIPS 203: ML-KEM-512/768/1024)
  +-- kylix-ml-dsa  (FIPS 204: ML-DSA-44/65/87)
  +-- kylix-slh-dsa (FIPS 205: SLH-DSA all SHAKE/SHA2 variants)
  |
  +-- kylix-pqc (re-export facade)
```

## Performance Notes

- Dev/test profiles use opt-level=2 for crypto crates (SLH-DSA is 10-15x slower at opt-level=0)
- Release: LTO + codegen-units=1 + panic=abort
- Benchmark via kylix-cli repo: `cargo bench -p kylix-bench`
