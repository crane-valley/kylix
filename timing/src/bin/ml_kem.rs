//! Constant-time verification for ML-KEM-768 decapsulation.
//!
//! Two dudect tests, each taking `MEASUREMENTS` timings in a single run:
//! - `decaps_768_valid_vs_invalid`: a valid ciphertext against the same
//!   ciphertext with one bit flipped (implicit rejection must not be visible).
//! - `decaps_768_fixed_vs_random`: one fixed valid ciphertext against
//!   uniformly random ciphertexts (catches input-dependent timing anywhere in
//!   decoding, decryption, re-encryption or comparison).
//!
//! Run with:
//! `cargo run --release --manifest-path timing/Cargo.toml --bin ml_kem`
//!
//! CI runs it through `timing/dudect-gate.sh`.

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

/// Inputs are generated a batch at a time, before any of them is timed, so
/// both classes are read from one buffer with the same access pattern and no
/// RNG or class-dependent copy runs between measurements. Batching rather
/// than one pool of `MEASUREMENTS` inputs keeps memory at about 9 MB.
const BATCH: usize = 8_000;
const _: () = assert!(MEASUREMENTS.is_multiple_of(BATCH));

fn measure_batches(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
    mut fill: impl FnMut(&mut BenchRng, Class, &mut [u8; CT_SIZE]),
) {
    let data = &*TEST_DATA;
    let mut classes = Vec::with_capacity(BATCH);
    let mut inputs = vec![[0u8; CT_SIZE]; BATCH];
    for _ in 0..MEASUREMENTS / BATCH {
        classes.clear();
        for input in inputs.iter_mut() {
            let class = random_class(rng);
            fill(rng, class, input);
            classes.push(class);
        }
        for (&class, input) in classes.iter().zip(&inputs) {
            let ct = Ciphertext::from_bytes(input).expect("ciphertext size");
            runner.run_one(class, || {
                MlKem768::decaps(black_box(&data.dk), black_box(&ct))
            });
        }
    }
}

fn decaps_768_valid_vs_invalid(runner: &mut CtRunner, rng: &mut BenchRng) {
    let data = &*TEST_DATA;
    measure_batches(runner, rng, |rng, class, input| {
        input.copy_from_slice(&data.valid[rng.gen_range(0..POOL_SIZE)]);
        let bit = rng.gen_range(0..CT_SIZE * 8);
        let flip = match class {
            Class::Left => 0,
            Class::Right => 1u8 << (bit % 8),
        };
        input[bit / 8] ^= flip;
    });
}

// Left entries are separate copies of the fixed ciphertext rather than one
// shared buffer, so the classes differ only in the input values.
fn decaps_768_fixed_vs_random(runner: &mut CtRunner, rng: &mut BenchRng) {
    let fixed = &TEST_DATA.valid[0];
    measure_batches(runner, rng, |rng, class, input| {
        rng.fill_bytes(input);
        if let Class::Left = class {
            input.copy_from_slice(fixed);
        }
    });
}

ctbench_main!(decaps_768_fixed_vs_random, decaps_768_valid_vs_invalid);
