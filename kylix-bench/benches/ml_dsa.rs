//! ML-DSA Benchmarks
//!
//! Benchmarks for all ML-DSA variants using the Criterion framework.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kylix_core::Signer;
use kylix_ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use rand::rng;

/// Test message for signing benchmarks.
const TEST_MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// Benchmark key generation for all ML-DSA variants.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA KeyGen");

    group.throughput(Throughput::Elements(1));

    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlDsa44::keygen(&mut rng).unwrap())
        })
    });

    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlDsa65::keygen(&mut rng).unwrap())
        })
    });

    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlDsa87::keygen(&mut rng).unwrap())
        })
    });

    group.finish();
}

/// Benchmark signing for all ML-DSA variants.
fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Sign");

    group.throughput(Throughput::Elements(1));

    // Pre-generate keys for signing benchmarks
    let (sk_44, _) = MlDsa44::keygen(&mut rng()).unwrap();
    let (sk_65, _) = MlDsa65::keygen(&mut rng()).unwrap();
    let (sk_87, _) = MlDsa87::keygen(&mut rng()).unwrap();

    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| black_box(MlDsa44::sign(&sk_44, TEST_MESSAGE).unwrap()))
    });

    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| black_box(MlDsa65::sign(&sk_65, TEST_MESSAGE).unwrap()))
    });

    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| black_box(MlDsa87::sign(&sk_87, TEST_MESSAGE).unwrap()))
    });

    group.finish();
}

/// Benchmark verification for all ML-DSA variants.
fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Verify");

    group.throughput(Throughput::Elements(1));

    // Pre-generate keys and signatures for verification benchmarks
    let mut rng = rng();

    let (sk_44, vk_44) = MlDsa44::keygen(&mut rng).unwrap();
    let sig_44 = MlDsa44::sign(&sk_44, TEST_MESSAGE).unwrap();

    let (sk_65, vk_65) = MlDsa65::keygen(&mut rng).unwrap();
    let sig_65 = MlDsa65::sign(&sk_65, TEST_MESSAGE).unwrap();

    let (sk_87, vk_87) = MlDsa87::keygen(&mut rng).unwrap();
    let sig_87 = MlDsa87::sign(&sk_87, TEST_MESSAGE).unwrap();

    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            MlDsa44::verify(
                black_box(&vk_44),
                black_box(TEST_MESSAGE),
                black_box(&sig_44),
            )
            .unwrap()
        })
    });

    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            MlDsa65::verify(
                black_box(&vk_65),
                black_box(TEST_MESSAGE),
                black_box(&sig_65),
            )
            .unwrap()
        })
    });

    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            MlDsa87::verify(
                black_box(&vk_87),
                black_box(TEST_MESSAGE),
                black_box(&sig_87),
            )
            .unwrap()
        })
    });

    group.finish();
}

/// Benchmark complete roundtrip (keygen + sign + verify).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Roundtrip");

    group.throughput(Throughput::Elements(1));

    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (sk, vk) = MlDsa44::keygen(&mut rng).unwrap();
            let sig = MlDsa44::sign(&sk, TEST_MESSAGE).unwrap();
            MlDsa44::verify(&vk, TEST_MESSAGE, &sig).unwrap()
        })
    });

    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (sk, vk) = MlDsa65::keygen(&mut rng).unwrap();
            let sig = MlDsa65::sign(&sk, TEST_MESSAGE).unwrap();
            MlDsa65::verify(&vk, TEST_MESSAGE, &sig).unwrap()
        })
    });

    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (sk, vk) = MlDsa87::keygen(&mut rng).unwrap();
            let sig = MlDsa87::sign(&sk, TEST_MESSAGE).unwrap();
            MlDsa87::verify(&vk, TEST_MESSAGE, &sig).unwrap()
        })
    });

    group.finish();
}

/// Benchmark key sizes (informational).
fn bench_sizes(c: &mut Criterion) {
    let group = c.benchmark_group("ML-DSA Sizes");

    // This is just to print sizes, not a real benchmark
    println!("\n=== ML-DSA Key/Signature Sizes ===");
    println!(
        "ML-DSA-44:  sk={} vk={} sig={}",
        MlDsa44::SIGNING_KEY_SIZE,
        MlDsa44::VERIFICATION_KEY_SIZE,
        MlDsa44::SIGNATURE_SIZE
    );
    println!(
        "ML-DSA-65:  sk={} vk={} sig={}",
        MlDsa65::SIGNING_KEY_SIZE,
        MlDsa65::VERIFICATION_KEY_SIZE,
        MlDsa65::SIGNATURE_SIZE
    );
    println!(
        "ML-DSA-87:  sk={} vk={} sig={}",
        MlDsa87::SIGNING_KEY_SIZE,
        MlDsa87::VERIFICATION_KEY_SIZE,
        MlDsa87::SIGNATURE_SIZE
    );
    println!();

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_roundtrip,
    bench_sizes,
);

criterion_main!(benches);
