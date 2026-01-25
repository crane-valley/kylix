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

### Notes

- SLH-DSA is hash-intensive and significantly slower than lattice-based ML-DSA
- Signing is the slowest operation due to hypertree computation
- "Small" variants (128s/192s/256s) have smaller signatures but are ~10x slower
- Enable `--features parallel` for multi-threaded FORS computation (improves signing performance)

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
| ML-DSA-65 Verify | 102 µs | < 100 µs | ✅ Pass |

### Notes

- SIMD optimizations (AVX2/NEON) are enabled by default for significant performance gains
- Results measured on Intel i5-13500 with `-C target-cpu=native`
- Sign performance includes rejection sampling loop iterations

---

## ML-KEM Performance

Benchmarks run with `cargo bench -p kylix-bench` using Criterion.

### Summary

| Algorithm | KeyGen | Encaps | Decaps | Roundtrip |
|-----------|--------|--------|--------|-----------|
| ML-KEM-512 | 18.4 µs | 17.6 µs | 24.3 µs | 62.4 µs |
| ML-KEM-768 | 31.3 µs | 28.7 µs | 38.2 µs | 104.1 µs |
| ML-KEM-1024 | 49.5 µs | 43.5 µs | 55.9 µs | 161.0 µs |

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
| ML-KEM-768 KeyGen | 31.3 µs | < 50 µs | ✅ Pass |
| ML-KEM-768 Encaps | 28.7 µs | < 60 µs | ✅ Pass |
| ML-KEM-768 Decaps | 38.2 µs | < 50 µs | ✅ Pass |

### Throughput

| Algorithm | KeyGen | Encaps | Decaps |
|-----------|--------|--------|--------|
| ML-KEM-512 | 54,320 ops/sec | 56,735 ops/sec | 41,096 ops/sec |
| ML-KEM-768 | 31,944 ops/sec | 34,788 ops/sec | 26,191 ops/sec |
| ML-KEM-1024 | 20,207 ops/sec | 22,976 ops/sec | 17,895 ops/sec |

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
