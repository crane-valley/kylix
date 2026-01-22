# ML-KEM Fuzz Testing

This directory contains fuzz targets for testing ML-KEM operations using `cargo-fuzz` and libFuzzer.

## Available Targets

- **fuzz_keygen**: Tests key generation with arbitrary seeds
- **fuzz_encaps**: Tests encapsulation with arbitrary encapsulation keys and messages
- **fuzz_decaps**: Tests decapsulation including implicit rejection for corrupted ciphertexts
- **fuzz_roundtrip**: Tests the complete keygen -> encaps -> decaps flow

## Requirements

- Rust nightly toolchain
- Linux or WSL (libFuzzer does not work natively on Windows)

## Running Fuzz Tests

```bash
# Install cargo-fuzz (if not already installed)
cargo +nightly install cargo-fuzz

# List available targets
cargo +nightly fuzz list

# Run a specific target (e.g., fuzz_roundtrip)
cargo +nightly fuzz run fuzz_roundtrip

# Run with a time limit (in seconds)
cargo +nightly fuzz run fuzz_roundtrip -- -max_total_time=60

# Run all targets sequentially
for target in fuzz_keygen fuzz_encaps fuzz_decaps fuzz_roundtrip; do
    cargo +nightly fuzz run $target -- -max_total_time=30
done
```

## Coverage

The fuzz targets cover:
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024 variants
- Key generation determinism
- Encapsulation determinism
- Decapsulation with valid ciphertexts
- Implicit rejection with corrupted ciphertexts
- Complete roundtrip correctness
