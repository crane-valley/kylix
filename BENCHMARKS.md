# Kylix Benchmark Results

## SLH-DSA Performance

Benchmarks for SLH-DSA "fast" variants only. The "small" variants are significantly slower.

### Summary

| Algorithm | KeyGen | Sign | Verify |
|-----------|--------|------|--------|
| SLH-DSA-SHAKE-128f | 2.62 ms | 61.1 ms | 3.66 ms |
| SLH-DSA-SHAKE-192f | 3.78 ms | 97.6 ms | 5.31 ms |
| SLH-DSA-SHAKE-256f | 10.0 ms | 201.3 ms | 5.41 ms |

### Key/Signature Sizes

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| SLH-DSA-SHAKE-128f | 32 bytes | 64 bytes | 17,088 bytes |
| SLH-DSA-SHAKE-192f | 48 bytes | 96 bytes | 35,664 bytes |
| SLH-DSA-SHAKE-256f | 64 bytes | 128 bytes | 49,856 bytes |

### Library Comparison (SLH-DSA-SHAKE-128f)

| Library | KeyGen | Sign | Verify |
|---------|--------|------|--------|
| RustCrypto | 2.35 ms | 56.3 ms | 3.34 ms |
| **Kylix** | **2.82 ms** | **61.4 ms** | **3.68 ms** |

### Notes

- SLH-DSA is hash-intensive and significantly slower than lattice-based ML-DSA
- Signing is the slowest operation due to hypertree computation
- "Small" variants (128s/192s/256s) have smaller signatures but are ~10x slower
- Enable `--features parallel` for multi-threaded FORS computation (improves signing performance)
- Kylix is ~10% slower than RustCrypto (room for optimization)

---

## ML-DSA Performance

Benchmarks run with `cargo bench -p kylix-bench --bench ml_dsa` using Criterion with SIMD enabled (default).

### Summary

| Algorithm | KeyGen | Sign | Verify |
|-----------|--------|------|--------|
| ML-DSA-44 | 60 µs | 115 µs | 60 µs |
| ML-DSA-65 | 97 µs | 165 µs | 102 µs |
| ML-DSA-87 | 155 µs | 260 µs | 165 µs |

### Key/Signature Sizes

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| ML-DSA-44 | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

### Performance vs Targets

| Operation | Kylix | Target | Status |
|-----------|-------|--------|--------|
| ML-DSA-65 KeyGen | 97 µs | - | ✅ |
| ML-DSA-65 Sign | 165 µs | < 200 µs | ✅ Pass |
| ML-DSA-65 Verify | 102 µs | < 100 µs | ⚠️ Close |

### Library Comparison (ML-DSA-65)

| Library | KeyGen | Sign | Verify |
|---------|--------|------|--------|
| libcrux | 45.3 µs | 117.3 µs | 34.5 µs |
| **Kylix** | **108.5 µs** | **274.8 µs** | **115.2 µs** |
| pqcrypto | 135.2 µs | 451.3 µs | 119.2 µs |
| RustCrypto | 264.0 µs | 293.8 µs | 47.6 µs |

### Notes

- SIMD optimizations (AVX2/NEON) are enabled by default for significant performance gains
- Results measured on Intel i5-13500 with `-C target-cpu=native`
- Sign performance includes rejection sampling loop iterations
- All benchmarks include RNG cost for fair comparison
- RustCrypto Verify is fast due to pre-computed expanded verification key

---

## ML-KEM Performance

Benchmarks run with `cargo bench -p kylix-bench` using Criterion with SIMD enabled (default).

### Summary

| Algorithm | KeyGen | Encaps | Decaps | Roundtrip |
|-----------|--------|--------|--------|-----------|
| ML-KEM-512 | 18.1 µs | 15.1 µs | 20.5 µs | 53.0 µs |
| ML-KEM-768 | 29.3 µs | 27.4 µs | 31.2 µs | 88.7 µs |
| ML-KEM-1024 | 53.7 µs | 39.7 µs | 47.0 µs | 140.0 µs |

### Key/Ciphertext Sizes

| Algorithm | Public Key | Private Key | Ciphertext | Shared Secret |
|-----------|------------|-------------|------------|---------------|
| ML-KEM-512 | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes |

### Performance vs Targets

Based on [PLANS.md](PLANS.md) performance goals:

| Operation | Kylix | Target | Status |
|-----------|-------|--------|--------|
| ML-KEM-768 KeyGen | 29.3 µs | < 50 µs | ✅ Pass |
| ML-KEM-768 Encaps | 27.4 µs | < 60 µs | ✅ Pass |
| ML-KEM-768 Decaps | 31.2 µs | < 50 µs | ✅ Pass |

### Library Comparison (ML-KEM-768)

| Library | KeyGen | Encaps | Decaps |
|---------|--------|--------|--------|
| libcrux | 11.8 µs | 11.1 µs | 11.3 µs |
| **Kylix** | **29.8 µs** | **22.6 µs** | **28.5 µs** |
| RustCrypto | 36.3 µs | 32.8 µs | 48.5 µs |
| pqcrypto | 41.5 µs | 41.5 µs | 52.2 µs |

### Notes

> - SIMD optimizations (AVX2/NEON) are enabled by default for significant performance gains
> - Results measured on Intel i5-13500 with `-C target-cpu=native`
> - All benchmarks include RNG cost for fair comparison
> - Kylix is faster than RustCrypto and pqcrypto, ~2.5x slower than libcrux (which uses formally verified, platform-specific assembly)

### Throughput

| Algorithm | KeyGen | Encaps | Decaps |
|-----------|--------|--------|--------|
| ML-KEM-512 | 55,200 ops/sec | 66,200 ops/sec | 48,800 ops/sec |
| ML-KEM-768 | 34,100 ops/sec | 36,500 ops/sec | 32,100 ops/sec |
| ML-KEM-1024 | 18,600 ops/sec | 25,200 ops/sec | 21,300 ops/sec |

## Comparison Benchmarks

Compare Kylix with other ML-KEM implementations:

```bash
# Compare with pqcrypto (C bindings to PQClean)
cargo bench -p kylix-bench --features compare-pqcrypto --bench comparison

# Compare with libcrux (formally verified Rust)
cargo bench -p kylix-bench --features compare-libcrux --bench comparison

# Compare with all available libraries
cargo bench -p kylix-bench --features compare-all --bench comparison
```

---

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench -p kylix-bench

# Run specific algorithm benchmarks
cargo bench -p kylix-bench --bench ml_kem
cargo bench -p kylix-bench --bench ml_dsa
cargo bench -p kylix-bench --bench slh_dsa

# Run SLH-DSA with parallel feature
cargo bench -p kylix-bench --bench slh_dsa --features parallel

# Run specific benchmark group
cargo bench -p kylix-bench -- "ML-KEM KeyGen"

# Save baseline for comparison
cargo bench -p kylix-bench -- --save-baseline main

# Compare against baseline
cargo bench -p kylix-bench -- --baseline main
```

## Environment

Benchmarks should be run on a quiet system with:
- CPU frequency scaling disabled (if possible)
- No other intensive processes running
- Same hardware for comparison purposes

## Notes

- Results are from optimized release builds with LTO enabled
- Randomness generation time is included in measurements
- Criterion uses statistical analysis with 100 samples per benchmark
