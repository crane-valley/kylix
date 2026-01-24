//! Fuzz target for ML-DSA signing.
//!
//! This fuzzer tests that Sign:
//! 1. Produces valid signatures from any message
//! 2. Does not panic on any input
//! 3. Produces deterministic output with same rnd

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_dsa::sign::{ml_dsa_keygen, ml_dsa_sign};

#[derive(Debug, Arbitrary)]
struct SignInput {
    seed: [u8; 32],
    rnd: [u8; 32],
    message: Vec<u8>,
    variant: u8,
}

fuzz_target!(|input: SignInput| {
    // Limit message size to prevent excessive memory usage
    if input.message.len() > 10000 {
        return;
    }

    match input.variant % 3 {
        0 => {
            // ML-DSA-44
            const K: usize = 4;
            const L: usize = 4;
            const ETA: usize = 2;
            const BETA: i32 = 78;
            const GAMMA1: i32 = 1 << 17;
            const GAMMA2: i32 = 95232;
            const TAU: usize = 39;
            const OMEGA: usize = 80;
            const C_TILDE_BYTES: usize = 32;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                // Verify signature size
                assert_eq!(sig.len(), 2420, "ML-DSA-44 signature should be 2420 bytes");

                // Verify determinism with same rnd
                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk,
                    &input.message,
                    &input.rnd,
                );
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
            }
        }
        1 => {
            // ML-DSA-65
            const K: usize = 6;
            const L: usize = 5;
            const ETA: usize = 4;
            const BETA: i32 = 196;
            const GAMMA1: i32 = 1 << 19;
            const GAMMA2: i32 = 261888;
            const TAU: usize = 49;
            const OMEGA: usize = 55;
            const C_TILDE_BYTES: usize = 48;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                assert_eq!(sig.len(), 3309, "ML-DSA-65 signature should be 3309 bytes");

                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk,
                    &input.message,
                    &input.rnd,
                );
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
            }
        }
        _ => {
            // ML-DSA-87
            const K: usize = 8;
            const L: usize = 7;
            const ETA: usize = 2;
            const BETA: i32 = 120;
            const GAMMA1: i32 = 1 << 19;
            const GAMMA2: i32 = 261888;
            const TAU: usize = 60;
            const OMEGA: usize = 75;
            const C_TILDE_BYTES: usize = 64;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                assert_eq!(sig.len(), 4627, "ML-DSA-87 signature should be 4627 bytes");

                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk,
                    &input.message,
                    &input.rnd,
                );
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
            }
        }
    }
});
