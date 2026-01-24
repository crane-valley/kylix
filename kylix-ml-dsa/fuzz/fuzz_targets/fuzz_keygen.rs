//! Fuzz target for ML-DSA key generation.
//!
//! This fuzzer tests that KeyGen:
//! 1. Produces valid keys from any random input
//! 2. Does not panic on any input
//! 3. Produces consistent output (deterministic)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_ml_dsa::sign::ml_dsa_keygen;

#[derive(Debug, Arbitrary)]
struct KeyGenInput {
    seed: [u8; 32],
    variant: u8, // 0 = ML-DSA-44, 1 = ML-DSA-65, 2 = ML-DSA-87
}

fuzz_target!(|input: KeyGenInput| {
    match input.variant % 3 {
        0 => {
            // ML-DSA-44: K=4, L=4, ETA=2
            let (sk, pk) = ml_dsa_keygen::<4, 4, 2>(&input.seed);
            // Verify determinism
            let (sk2, pk2) = ml_dsa_keygen::<4, 4, 2>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            // Verify key sizes
            assert_eq!(pk.len(), 1312, "ML-DSA-44 pk should be 1312 bytes");
            assert_eq!(sk.len(), 2560, "ML-DSA-44 sk should be 2560 bytes");
        }
        1 => {
            // ML-DSA-65: K=6, L=5, ETA=4
            let (sk, pk) = ml_dsa_keygen::<6, 5, 4>(&input.seed);
            let (sk2, pk2) = ml_dsa_keygen::<6, 5, 4>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            assert_eq!(pk.len(), 1952, "ML-DSA-65 pk should be 1952 bytes");
            assert_eq!(sk.len(), 4032, "ML-DSA-65 sk should be 4032 bytes");
        }
        _ => {
            // ML-DSA-87: K=8, L=7, ETA=2
            let (sk, pk) = ml_dsa_keygen::<8, 7, 2>(&input.seed);
            let (sk2, pk2) = ml_dsa_keygen::<8, 7, 2>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            assert_eq!(pk.len(), 2592, "ML-DSA-87 pk should be 2592 bytes");
            assert_eq!(sk.len(), 4896, "ML-DSA-87 sk should be 4896 bytes");
        }
    }
});
