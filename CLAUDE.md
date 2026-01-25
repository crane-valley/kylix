# CLAUDE.md

- Source code, comments, logs, error messages: English
- PR titles, summaries, and comments: English
- Create feature branch → commit → push → PR (merge is done by humans)

## CI Notes

- CI uses `-Dwarnings` so all warnings are treated as errors
- For WIP modules, add `#![allow(dead_code)]` at module top
- Doc comments: `[X]` is interpreted as a link reference by rustdoc; escape as `\[X\]`

## Pre-push Checklist

Run these commands before pushing (same as CI):

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Release

- Main crate is `kylix-pqc` (not `kylix` - that name was taken on crates.io)
- Create a GitHub Release with tag `vX.Y.Z` to auto-publish to crates.io
- Ensure `Cargo.toml` version matches the tag before release
- Release tag creation is done by humans

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
