//! Constant-time verification for ML-KEM decapsulation.
//!
//! Tests that decapsulation timing is independent of ciphertext validity
//! (implicit rejection must be constant-time).
//!
//! Run with: `cargo run --release -p kylix-timing --bin ml_kem`

use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use kylix_core::Kem;
use kylix_ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use once_cell::sync::Lazy;

/// Pre-generated key pair and ciphertexts for testing.
struct TestData {
    dk: DecapsulationKey,
    ct_valid: Ciphertext,
    ct_invalid: Ciphertext,
}

static TEST_DATA: Lazy<TestData> = Lazy::new(|| {
    let (dk, ek): (DecapsulationKey, EncapsulationKey) =
        MlKem768::keygen(&mut rand::rng()).expect("keygen failed");

    // Generate valid ciphertext
    let (ct_valid, _ss) = MlKem768::encaps(&ek, &mut rand::rng()).expect("encaps failed");

    // Create invalid ciphertext by corrupting the valid one
    let mut ct_invalid_bytes = [0u8; 1088]; // ML-KEM-768 ciphertext size
    ct_invalid_bytes.copy_from_slice(ct_valid.as_bytes());
    ct_invalid_bytes[0] ^= 0xff;
    ct_invalid_bytes[100] ^= 0xaa;
    let ct_invalid = Ciphertext::from_bytes(&ct_invalid_bytes).expect("invalid ct construction");

    TestData {
        dk,
        ct_valid,
        ct_invalid,
    }
});

/// Number of iterations per batch.
const ITERATIONS: usize = 10_000;

/// Test ML-KEM-768 decapsulation constant-time property.
///
/// Compares timing between:
/// - Left: valid ciphertext (decryption succeeds)
/// - Right: invalid ciphertext (implicit rejection triggered)
///
/// If constant-time, both paths should take identical time.
fn bench_decaps_768(runner: &mut CtRunner, rng: &mut BenchRng) {
    let data = &*TEST_DATA;

    // Pre-generate class assignments
    let mut classes = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        if rng.gen::<bool>() {
            classes.push(Class::Left);
        } else {
            classes.push(Class::Right);
        }
    }

    // Run the timing tests
    for class in classes {
        let ct = match class {
            Class::Left => &data.ct_valid,
            Class::Right => &data.ct_invalid,
        };

        runner.run_one(class, || {
            let _ = MlKem768::decaps(&data.dk, ct);
        });
    }
}

ctbench_main!(bench_decaps_768);
