//! Fuzz target for ML-DSA roundtrip (keygen -> sign -> verify).
//!
//! This fuzzer tests the complete flow:
//! 1. KeyGen produces valid keys
//! 2. Sign with those keys produces valid signatures
//! 3. Verify accepts valid signatures
//! 4. The entire flow is deterministic

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_dsa::sign::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};

#[derive(Debug, Arbitrary)]
struct RoundtripInput {
    seed: [u8; 32],
    rnd: [u8; 32],
    message: Vec<u8>,
    variant: u8,
}

fuzz_target!(|input: RoundtripInput| {
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

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                let valid = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk,
                    &input.message,
                    &sig,
                );
                assert!(valid, "Roundtrip failed: valid signature rejected for ML-DSA-44");

                // Full roundtrip determinism check
                let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk2,
                    &input.message,
                    &input.rnd,
                );
                let valid2 = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk2,
                    &input.message,
                    sig2.as_ref().unwrap(),
                );

                assert_eq!(sk, sk2, "KeyGen should be deterministic");
                assert_eq!(pk, pk2, "KeyGen should be deterministic");
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
                assert!(valid2, "Verification should be consistent");
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

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                let valid = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk,
                    &input.message,
                    &sig,
                );
                assert!(valid, "Roundtrip failed: valid signature rejected for ML-DSA-65");

                let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk2,
                    &input.message,
                    &input.rnd,
                );
                let valid2 = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk2,
                    &input.message,
                    sig2.as_ref().unwrap(),
                );

                assert_eq!(sk, sk2, "KeyGen should be deterministic");
                assert_eq!(pk, pk2, "KeyGen should be deterministic");
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
                assert!(valid2, "Verification should be consistent");
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

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(sig) = sig {
                let valid = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk,
                    &input.message,
                    &sig,
                );
                assert!(valid, "Roundtrip failed: valid signature rejected for ML-DSA-87");

                let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
                let sig2 = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &sk2,
                    &input.message,
                    &input.rnd,
                );
                let valid2 = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk2,
                    &input.message,
                    sig2.as_ref().unwrap(),
                );

                assert_eq!(sk, sk2, "KeyGen should be deterministic");
                assert_eq!(pk, pk2, "KeyGen should be deterministic");
                assert_eq!(sig, sig2.unwrap(), "Sign should be deterministic with same rnd");
                assert!(valid2, "Verification should be consistent");
            }
        }
    }
});
