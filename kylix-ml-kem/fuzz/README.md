# ML-KEM Fuzz Testing

This directory contains fuzz targets for testing ML-KEM operations using `cargo-fuzz` and libFuzzer.

## Available Targets

- **fuzz_keygen**: Key generation from arbitrary `d`/`z` seeds; checks determinism and key sizes
- **fuzz_encaps**: Encapsulation with an attacker-controlled encapsulation key of any length and
  content; checks that `EncapsulationKey::from_bytes` and `ml_kem_encaps` accept exactly the
  well-formed keys (length and modulus check) and that encapsulation is deterministic
- **fuzz_decaps**: Decapsulation with attacker-controlled decapsulation keys and ciphertexts of any
  length and content, including structured keys whose embedded hash matches and patched
  reference ciphertexts; checks accept/reject against the length, hash and modulus rules,
  typed/low-level agreement, and the implicit-rejection value `J(z || c)`
- **fuzz_roundtrip**: keygen -> encaps -> decaps with arbitrary seeds; checks shared-secret
  agreement and determinism

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

# Run a specific target (e.g., fuzz_decaps)
cargo +nightly fuzz run fuzz_decaps

# Run with a time limit (in seconds)
cargo +nightly fuzz run fuzz_decaps -- -max_total_time=60

# Run all targets sequentially
for target in fuzz_keygen fuzz_encaps fuzz_decaps fuzz_roundtrip; do
    cargo +nightly fuzz run $target -- -max_total_time=30
done
```

libFuzzer limits inputs to 4096 bytes (or the largest corpus input) unless `-max_len`
is given. The per-target values used in CI are in `.github/workflows/fuzz.yml`;
pass at least those so the fuzzer can reach full-size keys and ciphertexts.

## Coverage

All targets cover ML-KEM-512, ML-KEM-768 and ML-KEM-1024. Inputs an attacker controls in
practice (encapsulation keys, decapsulation keys, ciphertexts) are fuzzed as raw bytes by
`fuzz_encaps` and `fuzz_decaps`; the other targets only derive keys from fuzzed seeds.
