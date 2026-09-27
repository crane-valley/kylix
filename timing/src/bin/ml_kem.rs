//! Constant-time verification for ML-KEM-768 decapsulation.
//!
//! Two dudect tests, each taking `MEASUREMENTS` timings in one batch:
//! - `decaps_768_valid_vs_invalid`: a valid ciphertext against the same
//!   ciphertext with one bit flipped (implicit rejection must not be visible).
//! - `decaps_768_fixed_vs_random`: one fixed valid ciphertext against
//!   uniformly random ciphertexts (catches input-dependent timing anywhere in
//!   decoding, decryption, re-encryption or comparison).
//!
//! Run with:
//! `cargo run --release --manifest-path timing/Cargo.toml --bin ml_kem`
//!
//! CI evaluates the output with `timing/dudect-gate.sh`.

use std::hint::black_box;

use dudect_bencher::rand::{Rng, RngCore};
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use kylix_core::Kem;
use kylix_ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};

const CT_SIZE: usize = MlKem768::CIPHERTEXT_SIZE;

/// Timings per test. t grows with the square root of the sample count; 1M
/// keeps both tests at about two minutes in total on a desktop CPU, which
/// leaves room for a slower CI runner within the job timeout.
const MEASUREMENTS: usize = 1_000_000;

/// Distinct valid ciphertexts; enough that the left class is not a single
/// cached input.
const POOL_SIZE: usize = 1024;

struct TestData {
    dk: DecapsulationKey,
    valid: Vec<[u8; CT_SIZE]>,
}

static TEST_DATA: Lazy<TestData> = Lazy::new(|| {
    let mut rng = StdRng::from_seed([42u8; 32]);
    let (dk, ek): (DecapsulationKey, EncapsulationKey) =
        MlKem768::keygen(&mut rng).expect("keygen failed");

    let valid = (0..POOL_SIZE)
        .map(|_| {
            let (ct, _ss) = MlKem768::encaps(&ek, &mut rng).expect("encaps failed");
            let mut bytes = [0u8; CT_SIZE];
            bytes.copy_from_slice(ct.as_bytes());
            bytes
        })
        .collect();

    TestData { dk, valid }
});

fn random_class(rng: &mut BenchRng) -> Class {
    if rng.gen::<bool>() {
        Class::Left
    } else {
        Class::Right
    }
}

// Both classes are built into the same buffer and parsed the same way, so
// only the ciphertext contents differ between them.
fn time_decaps(runner: &mut CtRunner, class: Class, bytes: &[u8; CT_SIZE]) {
    let data = &*TEST_DATA;
    let ct = Ciphertext::from_bytes(bytes).expect("ciphertext size");
    runner.run_one(class, || {
        MlKem768::decaps(black_box(&data.dk), black_box(&ct))
    });
}

fn decaps_768_valid_vs_invalid(runner: &mut CtRunner, rng: &mut BenchRng) {
    let data = &*TEST_DATA;
    let mut buf = [0u8; CT_SIZE];
    for _ in 0..MEASUREMENTS {
        let class = random_class(rng);
        buf.copy_from_slice(&data.valid[rng.gen_range(0..POOL_SIZE)]);
        let bit = rng.gen_range(0..CT_SIZE * 8);
        let flip = match class {
            Class::Left => 0,
            Class::Right => 1u8 << (bit % 8),
        };
        buf[bit / 8] ^= flip;
        time_decaps(runner, class, &buf);
    }
}

fn decaps_768_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let data = &*TEST_DATA;
    let mut buf = [0u8; CT_SIZE];
    let mut random = [0u8; CT_SIZE];
    for _ in 0..MEASUREMENTS {
        let class = random_class(rng);
        rng.fill_bytes(&mut random);
        match class {
            Class::Left => buf.copy_from_slice(&data.valid[0]),
            Class::Right => buf.copy_from_slice(&random),
        }
        time_decaps(runner, class, &buf);
    }
}

ctbench_main!(decaps_768_fixed_vs_random, decaps_768_valid_vs_invalid);
