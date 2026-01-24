//! SLH-DSA Benchmarks
//!
//! Benchmarks for SLH-DSA "fast" variants using the Criterion framework.
//! Only the "f" (fast) variants are benchmarked as the "s" (small) variants
//! are significantly slower and would increase benchmark time excessively.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kylix_core::Signer;
use kylix_slh_dsa::{SlhDsaShake128f, SlhDsaShake192f, SlhDsaShake256f};
use rand::rng;

/// Test message for signing benchmarks.
const TEST_MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// Benchmark key generation for SLH-DSA fast variants.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA KeyGen");

    group.throughput(Throughput::Elements(1));
    // SLH-DSA keygen is slower, increase sample size time
    group.sample_size(10);

    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter_batched(
            rng,
            |mut rng| black_box(SlhDsaShake128f::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("SLH-DSA-SHAKE-192f", |b| {
        b.iter_batched(
            rng,
            |mut rng| black_box(SlhDsaShake192f::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("SLH-DSA-SHAKE-256f", |b| {
        b.iter_batched(
            rng,
            |mut rng| black_box(SlhDsaShake256f::keygen(&mut rng).unwrap()),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark signing for SLH-DSA fast variants.
fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA Sign");

    group.throughput(Throughput::Elements(1));
    // SLH-DSA signing is slower
    group.sample_size(10);

    // Pre-generate keys for signing benchmarks
    let mut rng = rng();
    let (sk_128f, _) = SlhDsaShake128f::keygen(&mut rng).unwrap();
    let (sk_192f, _) = SlhDsaShake192f::keygen(&mut rng).unwrap();
    let (sk_256f, _) = SlhDsaShake256f::keygen(&mut rng).unwrap();

    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter(|| black_box(SlhDsaShake128f::sign(&sk_128f, TEST_MESSAGE).unwrap()))
    });

    group.bench_function("SLH-DSA-SHAKE-192f", |b| {
        b.iter(|| black_box(SlhDsaShake192f::sign(&sk_192f, TEST_MESSAGE).unwrap()))
    });

    group.bench_function("SLH-DSA-SHAKE-256f", |b| {
        b.iter(|| black_box(SlhDsaShake256f::sign(&sk_256f, TEST_MESSAGE).unwrap()))
    });

    group.finish();
}

/// Benchmark verification for SLH-DSA fast variants.
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("SLH-DSA Verify");

    group.throughput(Throughput::Elements(1));
    // SLH-DSA verification is slower
    group.sample_size(10);

    // Pre-generate keys and signatures for verification benchmarks
    let mut rng = rng();

    let (sk_128f, vk_128f) = SlhDsaShake128f::keygen(&mut rng).unwrap();
    let sig_128f = SlhDsaShake128f::sign(&sk_128f, TEST_MESSAGE).unwrap();

    let (sk_192f, vk_192f) = SlhDsaShake192f::keygen(&mut rng).unwrap();
    let sig_192f = SlhDsaShake192f::sign(&sk_192f, TEST_MESSAGE).unwrap();

    let (sk_256f, vk_256f) = SlhDsaShake256f::keygen(&mut rng).unwrap();
    let sig_256f = SlhDsaShake256f::sign(&sk_256f, TEST_MESSAGE).unwrap();

    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter(|| {
            SlhDsaShake128f::verify(
                black_box(&vk_128f),
                black_box(TEST_MESSAGE),
                black_box(&sig_128f),
            )
            .unwrap()
        })
    });

    group.bench_function("SLH-DSA-SHAKE-192f", |b| {
        b.iter(|| {
            SlhDsaShake192f::verify(
                black_box(&vk_192f),
                black_box(TEST_MESSAGE),
                black_box(&sig_192f),
            )
            .unwrap()
        })
    });

    group.bench_function("SLH-DSA-SHAKE-256f", |b| {
        b.iter(|| {
            SlhDsaShake256f::verify(
                black_box(&vk_256f),
                black_box(TEST_MESSAGE),
                black_box(&sig_256f),
            )
            .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify,);

criterion_main!(benches);
