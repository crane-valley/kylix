# ML-DSA Fuzz Testing

This directory contains fuzz targets for testing ML-DSA operations using `cargo-fuzz` and libFuzzer.

## Available Targets

- **fuzz_keygen**: Key generation from arbitrary seeds; checks determinism and key sizes
- **fuzz_sign**: Signing with arbitrary messages and `rnd`; checks signature size and determinism
  for the same `rnd`
- **fuzz_verify**: Signs with a freshly generated key, then verifies the valid signature,
  a modified message (must reject), a single-byte signature corruption and a random
  full-size signature (must not panic)
- **fuzz_verify_bytes**: Attacker-controlled public keys and signatures of any length and
  content, against arbitrary keys or a fixed reference key; checks that `from_bytes`,
  `verify`, `expand` and `verify_expanded` agree with the low-level functions and that
  only the unmodified reference (key, message, signature) verifies
- **fuzz_roundtrip**: keygen -> sign -> verify with arbitrary inputs; checks acceptance and
  determinism

## Requirements

- Rust nightly toolchain
- cargo-fuzz (CI pins 0.13.1: `cargo install cargo-fuzz --version 0.13.1 --locked`)
- Linux or WSL (CI runs on Ubuntu). Native Windows MSVC builds also work when the
  MSVC `bin/Hostx64/x64` directory, which ships the ASan runtime DLL, is on `PATH`.

## Running Fuzz Tests

```bash
# Install cargo-fuzz (if not already installed)
cargo install cargo-fuzz --version 0.13.1 --locked

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

All targets cover ML-DSA-44, ML-DSA-65 and ML-DSA-87. Public keys and signatures are fuzzed
as raw bytes only by `fuzz_verify_bytes`; the other targets derive keys from fuzzed seeds.
Secret-key parsing (`SigningKey::from_bytes` with untrusted bytes) is not fuzzed.
