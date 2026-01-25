//! Comparison Benchmarks
//!
//! Benchmarks comparing Kylix with other ML-KEM implementations.
//!
//! Run with specific features:
//! ```bash
//! cargo bench -p kylix-bench --features compare-pqcrypto --bench comparison
//! cargo bench -p kylix-bench --features compare-rustcrypto --bench comparison
//! cargo bench -p kylix-bench --features compare-libcrux --bench comparison
//! cargo bench -p kylix-bench --features compare-all --bench comparison
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// Kylix
use kylix_core::Kem;
use kylix_ml_kem::MlKem768;

// RustCrypto ml-kem RNG wrapper (bridges getrandom 0.3 to rand_core 0.10)
// Implements infallible Rng trait required by ml-kem's CryptoRng bound
#[cfg(feature = "compare-rustcrypto")]
struct OsRng010;

#[cfg(feature = "compare-rustcrypto")]
impl rand_core_010::TryRng for OsRng010 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(getrandom_010::u32().unwrap_or_else(|e| panic!("getrandom failed: {e}")))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(getrandom_010::u64().unwrap_or_else(|e| panic!("getrandom failed: {e}")))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        getrandom_010::fill(dest).unwrap_or_else(|e| panic!("getrandom failed: {e}"));
        Ok(())
    }
}

#[cfg(feature = "compare-rustcrypto")]
impl rand_core_010::TryCryptoRng for OsRng010 {}

// Blanket impl for Rng is provided by rand_core when TryRng<Error = Infallible>

/// Benchmark ML-KEM-768 KeyGen across libraries.
fn bench_keygen_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768 KeyGen Comparison");

    // Kylix
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter_batched(
            rand::rng,
            |mut rng| black_box(MlKem768::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    // pqcrypto-mlkem
    #[cfg(feature = "compare-pqcrypto")]
    {
        use pqcrypto_mlkem::mlkem768;
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mlkem768::keypair()))
        });
    }

    // RustCrypto ml-kem (uses rand_core 0.10-rc via aliased dependency)
    #[cfg(feature = "compare-rustcrypto")]
    {
        use ml_kem::{KemCore, MlKem768 as RcMlKem768};
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter_batched(
                || OsRng010,
                |mut rng| black_box(RcMlKem768::generate(&mut rng)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    // libcrux-ml-kem (include RNG cost for fair comparison)
    #[cfg(feature = "compare-libcrux")]
    {
        use libcrux_ml_kem::mlkem768;
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter(|| {
                let randomness: [u8; 64] = rand::random();
                black_box(mlkem768::generate_key_pair(randomness))
            })
        });
    }

    group.finish();
}

/// Benchmark ML-KEM-768 Encaps across libraries.
fn bench_encaps_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768 Encaps Comparison");

    // Kylix
    let (_, ek_kylix) = MlKem768::keygen(&mut rand::rng()).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter_batched(
            rand::rng,
            |mut rng| black_box(MlKem768::encaps(&ek_kylix, &mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    // pqcrypto-mlkem
    #[cfg(feature = "compare-pqcrypto")]
    {
        use pqcrypto_mlkem::mlkem768;
        let (pk, _) = mlkem768::keypair();
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mlkem768::encapsulate(&pk)))
        });
    }

    // RustCrypto ml-kem (uses rand_core 0.10-rc via aliased dependency)
    #[cfg(feature = "compare-rustcrypto")]
    {
        use ml_kem::{kem::Encapsulate, KemCore, MlKem768 as RcMlKem768};
        let (_, ek_rc) = RcMlKem768::generate(&mut OsRng010);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter_batched(
                || OsRng010,
                |mut rng| black_box(ek_rc.encapsulate_with_rng(&mut rng)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    // libcrux-ml-kem (include RNG cost for fair comparison)
    #[cfg(feature = "compare-libcrux")]
    {
        use libcrux_ml_kem::mlkem768;
        let randomness: [u8; 64] = rand::random();
        let keypair = mlkem768::generate_key_pair(randomness);
        let pk = keypair.public_key();
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter(|| {
                let randomness: [u8; 32] = rand::random();
                black_box(mlkem768::encapsulate(pk, randomness))
            })
        });
    }

    group.finish();
}

/// Benchmark ML-KEM-768 Decaps across libraries.
fn bench_decaps_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768 Decaps Comparison");

    // Kylix
    let mut rng = rand::rng();
    let (dk_kylix, ek_kylix) = MlKem768::keygen(&mut rng).unwrap();
    let (ct_kylix, _) = MlKem768::encaps(&ek_kylix, &mut rng).unwrap();
    group.bench_function(BenchmarkId::new("Kylix", ""), |b| {
        b.iter(|| black_box(MlKem768::decaps(&dk_kylix, &ct_kylix).unwrap()))
    });

    // pqcrypto-mlkem
    #[cfg(feature = "compare-pqcrypto")]
    {
        use pqcrypto_mlkem::mlkem768;
        let (pk, sk) = mlkem768::keypair();
        let (_, ct) = mlkem768::encapsulate(&pk);
        group.bench_function(BenchmarkId::new("pqcrypto", ""), |b| {
            b.iter(|| black_box(mlkem768::decapsulate(&ct, &sk)))
        });
    }

    // RustCrypto ml-kem (uses rand_core 0.10-rc via aliased dependency)
    #[cfg(feature = "compare-rustcrypto")]
    {
        use ml_kem::{kem::Decapsulate, kem::Encapsulate, KemCore, MlKem768 as RcMlKem768};
        let (dk_rc, ek_rc) = RcMlKem768::generate(&mut OsRng010);
        let (ct_rc, _) = ek_rc.encapsulate_with_rng(&mut OsRng010);
        group.bench_function(BenchmarkId::new("RustCrypto", ""), |b| {
            b.iter(|| black_box(dk_rc.decapsulate(&ct_rc)))
        });
    }

    // libcrux-ml-kem
    #[cfg(feature = "compare-libcrux")]
    {
        use libcrux_ml_kem::mlkem768;
        let key_randomness: [u8; 64] = rand::random();
        let keypair = mlkem768::generate_key_pair(key_randomness);
        let enc_randomness: [u8; 32] = rand::random();
        let (ct, _) = mlkem768::encapsulate(keypair.public_key(), enc_randomness);
        group.bench_function(BenchmarkId::new("libcrux", ""), |b| {
            b.iter(|| black_box(mlkem768::decapsulate(keypair.private_key(), &ct)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen_comparison,
    bench_encaps_comparison,
    bench_decaps_comparison,
);

criterion_main!(benches);
