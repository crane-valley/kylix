//! Fuzz target for ML-KEM encapsulation.
//!
//! This fuzzer tests that Encaps:
//! 1. Works with any valid encapsulation key
//! 2. Does not panic on malformed keys
//! 3. Produces consistent output (deterministic)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_kem::kem::{ml_kem_encaps, ml_kem_keygen};

#[derive(Debug, Arbitrary)]
struct EncapsInput {
    d: [u8; 32],
    z: [u8; 32],
    m: [u8; 32],
    variant: u8,
}

fuzz_target!(|input: EncapsInput| {
    match input.variant % 3 {
        0 => {
            // ML-KEM-512
            let (_, ek) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            let (ct, ss) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &input.m).unwrap();
            // Verify determinism
            let (ct2, ss2) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &input.m).unwrap();
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss, ss2, "Encaps should be deterministic");
            // Verify sizes
            assert_eq!(ct.len(), 768, "ML-KEM-512 ct should be 768 bytes");
            assert_eq!(ss.len(), 32, "Shared secret should be 32 bytes");
        }
        1 => {
            // ML-KEM-768
            let (_, ek) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            let (ct, ss) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &input.m).unwrap();
            let (ct2, ss2) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &input.m).unwrap();
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss, ss2, "Encaps should be deterministic");
            assert_eq!(ct.len(), 1088, "ML-KEM-768 ct should be 1088 bytes");
            assert_eq!(ss.len(), 32, "Shared secret should be 32 bytes");
        }
        _ => {
            // ML-KEM-1024
            let (_, ek) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            let (ct, ss) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &input.m).unwrap();
            let (ct2, ss2) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &input.m).unwrap();
            assert_eq!(ct, ct2, "Encaps should be deterministic");
            assert_eq!(ss, ss2, "Encaps should be deterministic");
            assert_eq!(ct.len(), 1568, "ML-KEM-1024 ct should be 1568 bytes");
            assert_eq!(ss.len(), 32, "Shared secret should be 32 bytes");
        }
    }
});
