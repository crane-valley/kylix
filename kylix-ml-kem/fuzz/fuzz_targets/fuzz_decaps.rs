//! Fuzz target for ML-KEM decapsulation.
//!
//! This fuzzer tests that Decaps:
//! 1. Works with valid dk and ct
//! 2. Handles corrupted/malformed ciphertexts gracefully (implicit rejection)
//! 3. Produces consistent output (deterministic)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};

#[derive(Debug, Arbitrary)]
struct DecapsInput {
    d: [u8; 32],
    z: [u8; 32],
    m: [u8; 32],
    corrupt_byte: u8,
    corrupt_index: usize,
    variant: u8,
}

fuzz_target!(|input: DecapsInput| {
    match input.variant % 3 {
        0 => {
            // ML-KEM-512
            let (dk, ek) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            let (mut ct, ss_sender) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &input.m);

            // Test normal decapsulation
            let ss_receiver = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct);
            assert_eq!(ss_sender, ss_receiver, "Valid decaps should recover shared secret");

            // Verify determinism
            let ss_receiver2 = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct);
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");

            // Test implicit rejection with corrupted ciphertext
            if !ct.is_empty() {
                let idx = input.corrupt_index % ct.len();
                ct[idx] ^= input.corrupt_byte.wrapping_add(1);
                let ss_bad = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct);
                // Should still produce deterministic output (implicit rejection)
                let ss_bad2 = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct);
                assert_eq!(ss_bad, ss_bad2, "Implicit rejection should be deterministic");
            }
        }
        1 => {
            // ML-KEM-768
            let (dk, ek) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            let (mut ct, ss_sender) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &input.m);

            let ss_receiver = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct);
            assert_eq!(ss_sender, ss_receiver, "Valid decaps should recover shared secret");

            let ss_receiver2 = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct);
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");

            if !ct.is_empty() {
                let idx = input.corrupt_index % ct.len();
                ct[idx] ^= input.corrupt_byte.wrapping_add(1);
                let ss_bad = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct);
                let ss_bad2 = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct);
                assert_eq!(ss_bad, ss_bad2, "Implicit rejection should be deterministic");
            }
        }
        _ => {
            // ML-KEM-1024
            let (dk, ek) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            let (mut ct, ss_sender) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &input.m);

            let ss_receiver = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct);
            assert_eq!(ss_sender, ss_receiver, "Valid decaps should recover shared secret");

            let ss_receiver2 = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct);
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");

            if !ct.is_empty() {
                let idx = input.corrupt_index % ct.len();
                ct[idx] ^= input.corrupt_byte.wrapping_add(1);
                let ss_bad = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct);
                let ss_bad2 = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct);
                assert_eq!(ss_bad, ss_bad2, "Implicit rejection should be deterministic");
            }
        }
    }
});
