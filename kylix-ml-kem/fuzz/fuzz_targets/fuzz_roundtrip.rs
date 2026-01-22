//! Fuzz target for ML-KEM roundtrip (keygen -> encaps -> decaps).
//!
//! This fuzzer tests the complete flow:
//! 1. KeyGen produces valid keys
//! 2. Encaps with those keys produces valid ciphertext
//! 3. Decaps recovers the same shared secret
//! 4. The entire flow is deterministic

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};

#[derive(Debug, Arbitrary)]
struct RoundtripInput {
    d: [u8; 32],
    z: [u8; 32],
    m: [u8; 32],
    variant: u8,
}

fuzz_target!(|input: RoundtripInput| {
    match input.variant % 3 {
        0 => {
            // ML-KEM-512
            let (dk, ek) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            let (ct, ss_sender) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &input.m);
            let ss_receiver = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct);

            assert_eq!(
                ss_sender, ss_receiver,
                "Roundtrip failed: shared secrets don't match for ML-KEM-512"
            );

            // Full roundtrip determinism check
            let (dk2, ek2) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            let (ct2, ss_sender2) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek2, &input.m);
            let ss_receiver2 = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk2, &ct2);

            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss_sender, ss_sender2, "Encaps should be deterministic");
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");
        }
        1 => {
            // ML-KEM-768
            let (dk, ek) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            let (ct, ss_sender) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &input.m);
            let ss_receiver = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct);

            assert_eq!(
                ss_sender, ss_receiver,
                "Roundtrip failed: shared secrets don't match for ML-KEM-768"
            );

            let (dk2, ek2) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            let (ct2, ss_sender2) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek2, &input.m);
            let ss_receiver2 = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk2, &ct2);

            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss_sender, ss_sender2, "Encaps should be deterministic");
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");
        }
        _ => {
            // ML-KEM-1024
            let (dk, ek) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            let (ct, ss_sender) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &input.m);
            let ss_receiver = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct);

            assert_eq!(
                ss_sender, ss_receiver,
                "Roundtrip failed: shared secrets don't match for ML-KEM-1024"
            );

            let (dk2, ek2) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            let (ct2, ss_sender2) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek2, &input.m);
            let ss_receiver2 = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk2, &ct2);

            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss_sender, ss_sender2, "Encaps should be deterministic");
            assert_eq!(ss_receiver, ss_receiver2, "Decaps should be deterministic");
        }
    }
});
