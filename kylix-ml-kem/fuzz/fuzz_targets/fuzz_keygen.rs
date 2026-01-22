//! Fuzz target for ML-KEM key generation.
//!
//! This fuzzer tests that KeyGen:
//! 1. Produces valid keys from any random input
//! 2. Does not panic on any input
//! 3. Produces consistent output (deterministic)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_kem::kem::ml_kem_keygen;

#[derive(Debug, Arbitrary)]
struct KeyGenInput {
    d: [u8; 32],
    z: [u8; 32],
    variant: u8, // 0 = ML-KEM-512, 1 = ML-KEM-768, 2 = ML-KEM-1024
}

fuzz_target!(|input: KeyGenInput| {
    match input.variant % 3 {
        0 => {
            // ML-KEM-512
            let (dk, ek) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            // Verify determinism
            let (dk2, ek2) = ml_kem_keygen::<2, 3>(&input.d, &input.z);
            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            // Verify key sizes
            assert_eq!(ek.len(), 800, "ML-KEM-512 ek should be 800 bytes");
            assert_eq!(dk.len(), 1632, "ML-KEM-512 dk should be 1632 bytes");
        }
        1 => {
            // ML-KEM-768
            let (dk, ek) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            let (dk2, ek2) = ml_kem_keygen::<3, 2>(&input.d, &input.z);
            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            assert_eq!(ek.len(), 1184, "ML-KEM-768 ek should be 1184 bytes");
            assert_eq!(dk.len(), 2400, "ML-KEM-768 dk should be 2400 bytes");
        }
        _ => {
            // ML-KEM-1024
            let (dk, ek) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            let (dk2, ek2) = ml_kem_keygen::<4, 2>(&input.d, &input.z);
            assert_eq!(dk, dk2, "KeyGen should be deterministic");
            assert_eq!(ek, ek2, "KeyGen should be deterministic");
            assert_eq!(ek.len(), 1568, "ML-KEM-1024 ek should be 1568 bytes");
            assert_eq!(dk.len(), 3168, "ML-KEM-1024 dk should be 3168 bytes");
        }
    }
});
