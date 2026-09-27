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

NIST ACVP vector tests skip themselves when a crate's `tests/acvp/` directory
is absent (as in a partial source archive). Set `KYLIX_REQUIRE_ACVP=1` (as CI
does) to make an absent directory fail the tests instead. A vector file missing
from an existing `tests/acvp/` directory always fails the test that loads it.

```sh
KYLIX_REQUIRE_ACVP=1 cargo test --workspace --all-features
```

If your change touches secret-dependent code paths in ML-KEM, also run the
dudect timing harness, which lives in its own workspace under `timing/`:

```sh
cargo run --release --manifest-path timing/Cargo.toml --bin ml_kem
```

## Project Context

- [README.md](README.md) for package overview and public usage
- [ARCHITECTURE.md](ARCHITECTURE.md) for crate layout and design notes
- [CLAUDE.md](CLAUDE.md) for additional repository-specific guidance used by AI
  coding agents

## Pull Requests

- Use a clear title and describe the user-facing impact.
- Call out feature-flag, security, and compatibility implications explicitly.
- Maintainers handle merging and repository maintenance.
