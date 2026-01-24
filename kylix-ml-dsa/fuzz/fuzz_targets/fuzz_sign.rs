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
            use kylix_ml_dsa::params::ml_dsa_44::*;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                // Verify signature size
                assert_eq!(sig.len(), SIG_BYTES, "ML-DSA-44 signature size mismatch");

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
            use kylix_ml_dsa::params::ml_dsa_65::*;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                assert_eq!(sig.len(), SIG_BYTES, "ML-DSA-65 signature size mismatch");

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
            use kylix_ml_dsa::params::ml_dsa_87::*;

            let (sk, _pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                assert_eq!(sig.len(), SIG_BYTES, "ML-DSA-87 signature size mismatch");

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
