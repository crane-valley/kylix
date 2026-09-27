//! Constant-time verification for ML-DSA signing.
//!
//! Tests that signing timing does not leak information about the secret key.
//!
//! Note: ML-DSA uses rejection sampling, so signing time varies with the
//! number of rejected candidates. This test is informational and not part of
//! the CI gate.
//!
//! Run with:
//! `cargo run --release --manifest-path timing/Cargo.toml --bin ml_dsa`

use std::hint::black_box;

use dudect_bencher::rand::{Rng, RngCore};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use kylix_ml_dsa::ml_dsa_65::{MlDsa65, SigningKey, VerificationKey};
use kylix_ml_dsa::params::ml_dsa_65::{BETA, C_TILDE_BYTES, ETA, GAMMA1, GAMMA2, K, L, OMEGA, TAU};
use kylix_ml_dsa::sign::ml_dsa_sign;
use kylix_ml_dsa::Signer;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};

struct TestData {
    sk_left: SigningKey,
    sk_right: SigningKey,
}

static TEST_DATA: Lazy<TestData> = Lazy::new(|| {
    let mut rng = StdRng::from_seed([42u8; 32]);
    let (sk_left, _): (SigningKey, VerificationKey) =
        MlDsa65::keygen(&mut rng).expect("keygen failed");
    let (sk_right, _): (SigningKey, VerificationKey) =
        MlDsa65::keygen(&mut rng).expect("keygen failed");

    TestData { sk_left, sk_right }
});

const MESSAGE: &[u8] = b"constant-time test message for dudect verification";

const ITERATIONS: usize = 1_000;

// Deterministic signing fixes each key's rejection count for a given message,
// so the classes would differ by a constant number of loop iterations. A
// fresh hedged rnd per measurement makes the rejection count a fresh draw for
// both classes.
fn bench_sign_65(runner: &mut CtRunner, rng: &mut BenchRng) {
    let data = &*TEST_DATA;
    let mut rnd = [0u8; 32];

    for _ in 0..ITERATIONS {
        let (class, sk) = if rng.gen::<bool>() {
            (Class::Left, &data.sk_left)
        } else {
            (Class::Right, &data.sk_right)
        };
        rng.fill_bytes(&mut rnd);

        runner.run_one(class, || {
            ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                black_box(sk.as_bytes()),
                black_box(MESSAGE),
                black_box(&rnd),
            )
        });
    }
}

ctbench_main!(bench_sign_65);
