//! ML-DSA Comparison Benchmarks
//!
//! Benchmarks comparing Kylix with other ML-DSA implementations.
//!
//! Run with specific features:
//! ```bash
//! cargo bench -p kylix-bench --features compare-mldsa-pqcrypto --bench ml_dsa_comparison
//! cargo bench -p kylix-bench --features compare-mldsa-rustcrypto --bench ml_dsa_comparison
//! cargo bench -p kylix-bench --features compare-mldsa-libcrux --bench ml_dsa_comparison
//! cargo bench -p kylix-bench --features compare-mldsa-all --bench ml_dsa_comparison
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// Kylix
use kylix_core::Signer;
use kylix_ml_dsa::MlDsa65;

/// Test message for signing benchmarks.
const TEST_MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

// RustCrypto ml-dsa RNG wrapper (uses rand_core 0.6)
#[cfg(feature = "compare-mldsa-rustcrypto")]
struct OsRng06;

#[cfg(feature = "compare-mldsa-rustcrypto")]
impl rand_core_06::RngCore for OsRng06 {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom_02::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom_02::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom_02::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        getrandom_02::getrandom(dest).expect("getrandom failed");
        Ok(())
    }
}

#[cfg(feature = "compare-mldsa-rustcrypto")]
impl rand_core_06::CryptoRng for OsRng06 {}

/// Benchmark ML-DSA-65 KeyGen across libraries.
fn bench_keygen_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65 KeyGen Comparison");

    // Kylix
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter_batched(
            rand::rng,
            |mut rng| black_box(MlDsa65::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    // pqcrypto-mldsa
    #[cfg(feature = "compare-mldsa-pqcrypto")]
    {
        use pqcrypto_mldsa::mldsa65;
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mldsa65::keypair()))
        });
    }

    // RustCrypto ml-dsa
    #[cfg(feature = "compare-mldsa-rustcrypto")]
    {
        use ml_dsa::{KeyGen, MlDsa65 as RcMlDsa65};
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter_batched(
                || OsRng06,
                |mut rng| black_box(RcMlDsa65::key_gen(&mut rng)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    // libcrux-ml-dsa
    #[cfg(feature = "compare-mldsa-libcrux")]
    {
        use libcrux_ml_dsa::ml_dsa_65::generate_key_pair;
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter_batched(
                rand::random::<[u8; 32]>,
                |randomness| black_box(generate_key_pair(randomness)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark ML-DSA-65 Sign across libraries.
fn bench_sign_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65 Sign Comparison");

    // Kylix - sign is deterministic (no RNG needed)
    let (sk_kylix, _) = MlDsa65::keygen(&mut rand::rng()).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter(|| black_box(MlDsa65::sign(&sk_kylix, TEST_MESSAGE).unwrap()))
    });

    // pqcrypto-mldsa
    #[cfg(feature = "compare-mldsa-pqcrypto")]
    {
        use pqcrypto_mldsa::mldsa65;
        let (_, sk) = mldsa65::keypair();
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mldsa65::detached_sign(TEST_MESSAGE, &sk)))
        });
    }

    // RustCrypto ml-dsa
    #[cfg(feature = "compare-mldsa-rustcrypto")]
    {
        use ml_dsa::{signature::Signer, KeyGen, MlDsa65 as RcMlDsa65};
        let keypair = RcMlDsa65::key_gen(&mut OsRng06);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter(|| black_box(keypair.signing_key().sign(TEST_MESSAGE)))
        });
    }

    // libcrux-ml-dsa
    #[cfg(feature = "compare-mldsa-libcrux")]
    {
        use libcrux_ml_dsa::ml_dsa_65::{generate_key_pair, sign};
        let randomness: [u8; 32] = rand::random();
        let keypair = generate_key_pair(randomness);
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter_batched(
                rand::random::<[u8; 32]>,
                |signing_randomness| {
                    black_box(sign(
                        &keypair.signing_key,
                        TEST_MESSAGE,
                        b"", // empty context
                        signing_randomness,
                    ))
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark ML-DSA-65 Verify across libraries.
fn bench_verify_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-65 Verify Comparison");

    // Kylix
    let (sk_kylix, vk_kylix) = MlDsa65::keygen(&mut rand::rng()).unwrap();
    let sig_kylix = MlDsa65::sign(&sk_kylix, TEST_MESSAGE).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter(|| {
            MlDsa65::verify(
                black_box(&vk_kylix),
                black_box(TEST_MESSAGE),
                black_box(&sig_kylix),
            )
            .unwrap()
        })
    });

    // pqcrypto-mldsa
    #[cfg(feature = "compare-mldsa-pqcrypto")]
    {
        use pqcrypto_mldsa::mldsa65;
        let (pk, sk) = mldsa65::keypair();
        let sig = mldsa65::detached_sign(TEST_MESSAGE, &sk);
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mldsa65::verify_detached_signature(&sig, TEST_MESSAGE, &pk)))
        });
    }

    // RustCrypto ml-dsa
    #[cfg(feature = "compare-mldsa-rustcrypto")]
    {
        use ml_dsa::{
            signature::{Signer, Verifier},
            KeyGen, MlDsa65 as RcMlDsa65,
        };
        let keypair = RcMlDsa65::key_gen(&mut OsRng06);
        let sig_rc = keypair.signing_key().sign(TEST_MESSAGE);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter(|| black_box(keypair.verifying_key().verify(TEST_MESSAGE, &sig_rc)))
        });
    }

    // libcrux-ml-dsa
    #[cfg(feature = "compare-mldsa-libcrux")]
    {
        use libcrux_ml_dsa::ml_dsa_65::{generate_key_pair, sign, verify};
        let key_randomness: [u8; 32] = rand::random();
        let keypair = generate_key_pair(key_randomness);
        let signing_randomness: [u8; 32] = rand::random();
        let sig = sign(&keypair.signing_key, TEST_MESSAGE, b"", signing_randomness).unwrap();
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter(|| {
                black_box(verify(
                    &keypair.verification_key,
                    TEST_MESSAGE,
                    b"", // empty context
                    &sig,
                ))
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen_comparison,
    bench_sign_comparison,
    bench_verify_comparison,
);

criterion_main!(benches);
