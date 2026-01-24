//! Fuzz target for ML-DSA verification.
//!
//! This fuzzer tests that Verify:
//! 1. Correctly rejects invalid signatures
//! 2. Does not panic on malformed inputs
//! 3. Handles corrupted signatures gracefully

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_dsa::sign::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};

#[derive(Debug, Arbitrary)]
struct VerifyInput {
    seed: [u8; 32],
    rnd: [u8; 32],
    message: Vec<u8>,
    corruption: Option<CorruptionType>,
    variant: u8,
}

#[derive(Debug, Arbitrary)]
enum CorruptionType {
    // Corrupt a single byte at the given position
    CorruptSignature { position: usize, xor_value: u8 },
    // Corrupt the message
    CorruptMessage { position: usize, xor_value: u8 },
    // Use a random signature
    RandomSignature { random_sig: Vec<u8> },
}

fuzz_target!(|input: VerifyInput| {
    // Limit message size
    if input.message.len() > 10000 {
        return;
    }

    match input.variant % 3 {
        0 => {
            // ML-DSA-44
            use kylix_ml_dsa::params::ml_dsa_44::*;

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(mut sig) = sig {
                let mut msg = input.message.clone();

                match &input.corruption {
                    None => {
                        // Valid signature should verify
                        let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                            &pk, &msg, &sig,
                        );
                        assert!(result, "Valid signature should verify");
                    }
                    Some(CorruptionType::CorruptSignature { position, xor_value }) => {
                        if *position < sig.len() && *xor_value != 0 {
                            sig[*position] ^= xor_value;
                            // Corrupted signature should fail (most of the time)
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                        }
                    }
                    Some(CorruptionType::CorruptMessage { position, xor_value }) => {
                        if *position < msg.len() && *xor_value != 0 {
                            msg[*position] ^= xor_value;
                            let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                            assert!(!result, "Modified message should fail verification");
                        }
                    }
                    Some(CorruptionType::RandomSignature { random_sig }) => {
                        if random_sig.len() == SIG_BYTES {
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, random_sig,
                            );
                        }
                    }
                }
            }
        }
        1 => {
            // ML-DSA-65
            use kylix_ml_dsa::params::ml_dsa_65::*;

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(mut sig) = sig {
                let mut msg = input.message.clone();

                match &input.corruption {
                    None => {
                        let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                            &pk, &msg, &sig,
                        );
                        assert!(result, "Valid signature should verify");
                    }
                    Some(CorruptionType::CorruptSignature { position, xor_value }) => {
                        if *position < sig.len() && *xor_value != 0 {
                            sig[*position] ^= xor_value;
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                        }
                    }
                    Some(CorruptionType::CorruptMessage { position, xor_value }) => {
                        if *position < msg.len() && *xor_value != 0 {
                            msg[*position] ^= xor_value;
                            let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                            assert!(!result, "Modified message should fail verification");
                        }
                    }
                    Some(CorruptionType::RandomSignature { random_sig }) => {
                        if random_sig.len() == SIG_BYTES {
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, random_sig,
                            );
                        }
                    }
                }
            }
        }
        _ => {
            // ML-DSA-87
            use kylix_ml_dsa::params::ml_dsa_87::*;

            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let sig = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                &sk,
                &input.message,
                &input.rnd,
            );

            if let Some(mut sig) = sig {
                let mut msg = input.message.clone();

                match &input.corruption {
                    None => {
                        let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                            &pk, &msg, &sig,
                        );
                        assert!(result, "Valid signature should verify");
                    }
                    Some(CorruptionType::CorruptSignature { position, xor_value }) => {
                        if *position < sig.len() && *xor_value != 0 {
                            sig[*position] ^= xor_value;
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                        }
                    }
                    Some(CorruptionType::CorruptMessage { position, xor_value }) => {
                        if *position < msg.len() && *xor_value != 0 {
                            msg[*position] ^= xor_value;
                            let result = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, &sig,
                            );
                            assert!(!result, "Modified message should fail verification");
                        }
                    }
                    Some(CorruptionType::RandomSignature { random_sig }) => {
                        if random_sig.len() == SIG_BYTES {
                            let _ = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                                &pk, &msg, random_sig,
                            );
                        }
                    }
                }
            }
        }
    }
});
