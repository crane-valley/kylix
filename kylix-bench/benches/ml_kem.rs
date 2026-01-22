//! ML-KEM Benchmarks
//!
//! Benchmarks for all ML-KEM variants using the Criterion framework.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kylix_core::Kem;
use kylix_ml_kem::{MlKem1024, MlKem512, MlKem768};
use rand::rng;

/// Benchmark key generation for all ML-KEM variants.
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM KeyGen");

    group.throughput(Throughput::Elements(1));

    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlKem512::keygen(&mut rng).unwrap())
        })
    });

    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlKem768::keygen(&mut rng).unwrap())
        })
    });

    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let mut rng = rng();
            black_box(MlKem1024::keygen(&mut rng).unwrap())
        })
    });

    group.finish();
}

/// Benchmark encapsulation for all ML-KEM variants.
fn bench_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Encaps");

    group.throughput(Throughput::Elements(1));

    // Pre-generate keys for encapsulation benchmarks
    let (_, ek_512) = MlKem512::keygen(&mut rng()).unwrap();
    let (_, ek_768) = MlKem768::keygen(&mut rng()).unwrap();
    let (_, ek_1024) = MlKem1024::keygen(&mut rng()).unwrap();

    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let mut thread_rng = rng();
            black_box(MlKem512::encaps(&ek_512, &mut thread_rng).unwrap())
        })
    });

    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let mut thread_rng = rng();
            black_box(MlKem768::encaps(&ek_768, &mut thread_rng).unwrap())
        })
    });

    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let mut thread_rng = rng();
            black_box(MlKem1024::encaps(&ek_1024, &mut thread_rng).unwrap())
        })
    });

    group.finish();
}

/// Benchmark decapsulation for all ML-KEM variants.
fn bench_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Decaps");

    group.throughput(Throughput::Elements(1));

    // Pre-generate keys and ciphertexts for decapsulation benchmarks
    let mut rng = rng();

    let (dk_512, ek_512) = MlKem512::keygen(&mut rng).unwrap();
    let (ct_512, _) = MlKem512::encaps(&ek_512, &mut rng).unwrap();

    let (dk_768, ek_768) = MlKem768::keygen(&mut rng).unwrap();
    let (ct_768, _) = MlKem768::encaps(&ek_768, &mut rng).unwrap();

    let (dk_1024, ek_1024) = MlKem1024::keygen(&mut rng).unwrap();
    let (ct_1024, _) = MlKem1024::encaps(&ek_1024, &mut rng).unwrap();

    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| black_box(MlKem512::decaps(&dk_512, &ct_512).unwrap()))
    });

    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| black_box(MlKem768::decaps(&dk_768, &ct_768).unwrap()))
    });

    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| black_box(MlKem1024::decaps(&dk_1024, &ct_1024).unwrap()))
    });

    group.finish();
}

/// Benchmark complete roundtrip (keygen + encaps + decaps).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Roundtrip");

    group.throughput(Throughput::Elements(1));

    group.bench_function("ML-KEM-512", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (dk, ek) = MlKem512::keygen(&mut rng).unwrap();
            let (ct, _ss_sender) = MlKem512::encaps(&ek, &mut rng).unwrap();
            black_box(MlKem512::decaps(&dk, &ct).unwrap())
        })
    });

    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (dk, ek) = MlKem768::keygen(&mut rng).unwrap();
            let (ct, _ss_sender) = MlKem768::encaps(&ek, &mut rng).unwrap();
            black_box(MlKem768::decaps(&dk, &ct).unwrap())
        })
    });

    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let mut rng = rng();
            let (dk, ek) = MlKem1024::keygen(&mut rng).unwrap();
            let (ct, _ss_sender) = MlKem1024::encaps(&ek, &mut rng).unwrap();
            black_box(MlKem1024::decaps(&dk, &ct).unwrap())
        })
    });

    group.finish();
}

/// Benchmark key sizes (informational).
fn bench_sizes(c: &mut Criterion) {
    let group = c.benchmark_group("ML-KEM Sizes");

    // This is just to print sizes, not a real benchmark
    println!("\n=== ML-KEM Key/Ciphertext Sizes ===");
    println!(
        "ML-KEM-512:  ek={} dk={} ct={}",
        MlKem512::ENCAPSULATION_KEY_SIZE,
        MlKem512::DECAPSULATION_KEY_SIZE,
        MlKem512::CIPHERTEXT_SIZE
    );
    println!(
        "ML-KEM-768:  ek={} dk={} ct={}",
        MlKem768::ENCAPSULATION_KEY_SIZE,
        MlKem768::DECAPSULATION_KEY_SIZE,
        MlKem768::CIPHERTEXT_SIZE
    );
    println!(
        "ML-KEM-1024: ek={} dk={} ct={}",
        MlKem1024::ENCAPSULATION_KEY_SIZE,
        MlKem1024::DECAPSULATION_KEY_SIZE,
        MlKem1024::CIPHERTEXT_SIZE
    );
    println!();

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encaps,
    bench_decaps,
    bench_roundtrip,
    bench_sizes,
);

criterion_main!(benches);
