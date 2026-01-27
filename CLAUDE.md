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
3. `cargo test --workspace --exclude kylix-slh-dsa` - Run tests (excluding slow SLH-DSA tests)

During development, run `cargo fmt --all` frequently (for example, after each edit) to keep formatting consistent and get fast feedback.

## Release

- Main crate is `kylix-pqc` (not `kylix` - that name was taken on crates.io)
- Create a GitHub Release with tag `vX.Y.Z` to auto-publish to crates.io
- Ensure `Cargo.toml` version matches the tag before release
- Release tag creation is done by humans

### Selective Release

Use tag suffixes for selective releases:

| Tag | CLI Binaries | crates.io |
|-----|--------------|-----------|
| `vX.Y.Z` | Yes | Yes |
| `vX.Y.Z-cli` | Yes | No |
| `vX.Y.Z-crates` | No | Yes |

**CLI-only release** (e.g., CLI bug fixes without library changes):
1. Update `CHANGELOG.md` with CLI changes under a new version section
2. Create and push tag:
   ```bash
   git tag v0.4.2-cli
   git push origin v0.4.2-cli
   ```
3. Result:
   - Cargo.toml version stays at `0.4.2` (suffix is stripped for cargo-dist)
   - Creates GitHub Release `v0.4.2-cli` with CLI binaries
   - Skips crates.io publish

**Crates-only release** (e.g., library fixes without CLI rebuild):
1. Update `Cargo.toml` version to match the `vX.Y.Z` part of the new tag (e.g., `0.4.2` → `0.4.3`)
2. Update `CHANGELOG.md` with library changes
3. Create and push tag:
   ```bash
   git tag v0.4.3-crates
   git push origin v0.4.3-crates
   ```
4. Result:
   - Publishes to crates.io
   - Skips CLI binary build (no GitHub Release created)

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
