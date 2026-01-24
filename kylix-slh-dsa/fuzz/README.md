# SLH-DSA Fuzz Testing

This directory contains fuzz targets for testing SLH-DSA operations using `cargo-fuzz` and libFuzzer.

## Available Targets

- **fuzz_keygen**: Tests key generation with arbitrary seeds
- **fuzz_sign**: Tests signing with arbitrary messages and randomness
- **fuzz_verify**: Tests verification including corrupted signatures/messages
- **fuzz_roundtrip**: Tests the complete keygen -> sign -> verify flow

## Requirements

- Rust nightly toolchain
- Linux or WSL (libFuzzer does not work natively on Windows)

## Running Fuzz Tests

```bash
# Install cargo-fuzz (if not already installed)
cargo +nightly install cargo-fuzz

# Navigate to the fuzz directory
cd kylix-slh-dsa/fuzz

# List available targets
cargo +nightly fuzz list

# Run a specific target (e.g., fuzz_roundtrip)
cargo +nightly fuzz run fuzz_roundtrip

# Run with a time limit (in seconds)
cargo +nightly fuzz run fuzz_roundtrip -- -max_total_time=60

# Run all targets sequentially
for target in fuzz_keygen fuzz_sign fuzz_verify fuzz_roundtrip; do
    cargo +nightly fuzz run $target -- -max_total_time=30
done
```

## Coverage

The fuzz targets cover:
- SLH-DSA-SHAKE-128f variant (fast variant for efficient fuzzing)
- Key generation determinism
- Signing with randomized opt_rand
- Verification with valid signatures
- Rejection of corrupted signatures
- Rejection of modified messages
- Complete roundtrip correctness
