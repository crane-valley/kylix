//! SLH-DSA Comparison Benchmarks
//!
//! Benchmarks comparing Kylix with other SLH-DSA implementations.
//! Only SLH-DSA-SHAKE-128f (fast variant) is benchmarked for comparison.
//!
//! Run with specific features:
//! ```bash
//! cargo bench -p kylix-bench --features compare-slhdsa-rustcrypto --bench slh_dsa_comparison
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// Kylix
use kylix_core::Signer;
use kylix_slh_dsa::SlhDsaShake128f;

/// Test message for signing benchmarks.
const TEST_MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

// RustCrypto slh-dsa RNG wrapper (uses rand_core 0.6)
#[cfg(feature = "compare-slhdsa-rustcrypto")]
struct OsRng06;

#[cfg(feature = "compare-slhdsa-rustcrypto")]
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

#[cfg(feature = "compare-slhdsa-rustcrypto")]
impl rand_core_06::CryptoRng for OsRng06 {}

/// Benchmark SLH-DSA-SHAKE-128f KeyGen across libraries.
fn bench_keygen_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA-SHAKE-128f KeyGen Comparison");
    // SLH-DSA is slower, reduce sample size
    group.sample_size(10);

    // Kylix
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter_batched(
            rand::rng,
            |mut rng| black_box(SlhDsaShake128f::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    // RustCrypto slh-dsa
    #[cfg(feature = "compare-slhdsa-rustcrypto")]
    {
        use slh_dsa::{Shake128f, SigningKey};
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter_batched(
                || OsRng06,
                |mut rng| black_box(SigningKey::<Shake128f>::new(&mut rng)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark SLH-DSA-SHAKE-128f Sign across libraries.
fn bench_sign_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA-SHAKE-128f Sign Comparison");
    // SLH-DSA signing is slower
    group.sample_size(10);

    // Kylix
    let (sk_kylix, _) = SlhDsaShake128f::keygen(&mut rand::rng()).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter(|| black_box(SlhDsaShake128f::sign(&sk_kylix, TEST_MESSAGE).unwrap()))
    });

    // RustCrypto slh-dsa
    #[cfg(feature = "compare-slhdsa-rustcrypto")]
    {
        use slh_dsa::{signature::RandomizedSigner, Shake128f, SigningKey};
        let sk_rc = SigningKey::<Shake128f>::new(&mut OsRng06);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter_batched(
                || OsRng06,
                |mut rng| black_box(sk_rc.sign_with_rng(&mut rng, TEST_MESSAGE)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

/// Benchmark SLH-DSA-SHAKE-128f Verify across libraries.
fn bench_verify_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA-SHAKE-128f Verify Comparison");
    // SLH-DSA verification is slower
    group.sample_size(10);

    // Kylix
    let (sk_kylix, vk_kylix) = SlhDsaShake128f::keygen(&mut rand::rng()).unwrap();
    let sig_kylix = SlhDsaShake128f::sign(&sk_kylix, TEST_MESSAGE).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter(|| {
            SlhDsaShake128f::verify(
                black_box(&vk_kylix),
                black_box(TEST_MESSAGE),
                black_box(&sig_kylix),
            )
            .unwrap()
        })
    });

    // RustCrypto slh-dsa
    #[cfg(feature = "compare-slhdsa-rustcrypto")]
    {
        use slh_dsa::{
            signature::{Keypair, RandomizedSigner, Verifier},
            Shake128f, SigningKey,
        };
        let sk_rc = SigningKey::<Shake128f>::new(&mut OsRng06);
        let vk_rc = sk_rc.verifying_key();
        let sig_rc = sk_rc.sign_with_rng(&mut OsRng06, TEST_MESSAGE);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter(|| black_box(vk_rc.verify(TEST_MESSAGE, &sig_rc)))
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
