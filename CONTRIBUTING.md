# Contributing to Kylix

Thanks for contributing.

## Before You Open A PR

- Keep changes focused and scoped to a single concern when possible.
- Update docs and tests alongside behavior changes.
- Follow the security guidance in [SECURITY.md](SECURITY.md) when handling keys,
  seeds, or other sensitive material.

## Required Checks

Run these commands before opening a PR:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
```

If your change touches `no_std` behavior or feature gating, also verify the
affected crate builds without default features.

## Project Context

- [README.md](README.md) for package overview and public usage
- [ARCHITECTURE.md](ARCHITECTURE.md) for crate layout and design notes
- [CLAUDE.md](CLAUDE.md) for additional repository-specific guidance used by AI
  coding agents

## Pull Requests

- Use a clear title and describe the user-facing impact.
- Call out feature-flag, security, and compatibility implications explicitly.
- Maintainers handle merging and repository maintenance.
