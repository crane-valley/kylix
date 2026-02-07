# CLAUDE.md

- Source code, comments, logs, error messages: English
- PR titles, summaries, and comments: English
- Create feature branch → commit → push → PR (merge is done by humans)

## CI Notes

- CI uses `-Dwarnings` so all warnings are treated as errors
- For WIP modules, add `#![allow(dead_code)]` at module top
- Doc comments: `[X]` is interpreted as a link reference by rustdoc; escape as `\[X\]`

## Code Quality Rules

Before committing or creating a PR, always run:
1. `cargo fmt --all` - Format all code
2. `cargo clippy --all-targets --all-features -- -D warnings` - Check for lints
3. `cargo clippy --all-targets --no-default-features -- -D warnings` - Check no_std build
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

1. **Update `.github/workflows/release.yml`**: Add a publish step for the new crate in the correct dependency order (before crates that depend on it)
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
