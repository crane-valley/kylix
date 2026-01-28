//! Constant-time verification for ML-DSA signing.
//!
//! Tests that signing timing does not leak information about the secret key.
//!
//! Note: ML-DSA uses rejection sampling, so signing time varies by message.
//! This test checks that timing doesn't depend on the secret key bits.
//!
//! Run with: `cargo run --release -p kylix-timing --bin ml_dsa`

use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use kylix_ml_dsa::dsa65::{MlDsa65, SigningKey, VerificationKey};
use kylix_ml_dsa::Signer;
use once_cell::sync::Lazy;

/// Pre-generated key pairs for testing.
struct TestData {
    sk_left: SigningKey,
    sk_right: SigningKey,
}

static TEST_DATA: Lazy<TestData> = Lazy::new(|| {
    let (sk_left, _): (SigningKey, VerificationKey) =
        MlDsa65::keygen(&mut rand::rng()).expect("keygen failed");
    let (sk_right, _): (SigningKey, VerificationKey) =
        MlDsa65::keygen(&mut rand::rng()).expect("keygen failed");

    TestData { sk_left, sk_right }
});

/// Fixed test message.
const MESSAGE: &[u8] = b"constant-time test message for dudect verification";

/// Number of iterations per batch.
const ITERATIONS: usize = 1_000; // Lower than ML-KEM due to slower signing

/// Test ML-DSA-65 signing constant-time property.
///
/// Compares timing between two different secret keys signing the same message.
/// If constant-time, secret key content should not affect timing.
fn bench_sign_65(runner: &mut CtRunner, rng: &mut BenchRng) {
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
        let sk = match class {
            Class::Left => &data.sk_left,
            Class::Right => &data.sk_right,
        };

        runner.run_one(class, || {
            let _ = MlDsa65::sign(sk, MESSAGE);
        });
    }
}

ctbench_main!(bench_sign_65);
