# SLH-DSA Fuzz Testing

This directory contains fuzz targets for testing SLH-DSA operations using `cargo-fuzz` and libFuzzer.

## Available Targets

- **fuzz_keygen**: Key generation from a seeded RNG; checks key sizes
- **fuzz_sign**: Signing arbitrary messages with a key from a seeded RNG; checks signature size
- **fuzz_verify**: Signs with a freshly generated key, then checks that the valid signature
  verifies and that a modified message or a different key is rejected
- **fuzz_verify_bytes**: Attacker-controlled public keys and signatures of any length and
  content, against arbitrary keys or a fixed reference key; checks `from_bytes`, typed and
  low-level `verify` agreement, and that only the unmodified reference (key, message,
  signature) verifies
- **fuzz_roundtrip**: keygen -> sign -> verify with a seeded RNG; checks acceptance and
  rejection of a modified message

## Requirements

- Rust nightly toolchain
- cargo-fuzz (CI pins 0.13.1: `cargo install cargo-fuzz --version 0.13.1 --locked`)
- Linux or WSL (CI runs on Ubuntu). Native Windows MSVC builds also work when the
  MSVC `bin/Hostx64/x64` directory, which ships the ASan runtime DLL, is on `PATH`.

## Running Fuzz Tests

```bash
# Install cargo-fuzz (if not already installed)
cargo install cargo-fuzz --version 0.13.1 --locked

# Navigate to the crate directory
cd kylix-slh-dsa

# List available targets
cargo +nightly fuzz list

# Run a specific target (e.g., fuzz_verify_bytes)
cargo +nightly fuzz run fuzz_verify_bytes

# Run with a time limit (in seconds)
cargo +nightly fuzz run fuzz_verify_bytes -- -max_total_time=60

# Run all targets sequentially
for target in fuzz_keygen fuzz_sign fuzz_verify fuzz_verify_bytes fuzz_roundtrip; do
    cargo +nightly fuzz run $target -- -max_total_time=30
done
```

libFuzzer limits inputs to 4096 bytes (or the largest corpus input) unless `-max_len`
is given. The per-target values used in CI are in `.github/workflows/fuzz.yml`;
pass at least those so the fuzzer can reach full-size keys and signatures.

## Coverage

`fuzz_verify_bytes` covers SLH-DSA-SHAKE-128f and SLH-DSA-SHA2-128f; the other targets
cover SLH-DSA-SHAKE-128f only. The fast 128f parameter sets keep executions per second
usable; the other parameter sets share the same code with different constants and are not
fuzzed. Signing is deterministic (no `opt_rand`) in every target.
