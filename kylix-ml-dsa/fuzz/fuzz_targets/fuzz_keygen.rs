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
            // ML-DSA-44
            use kylix_ml_dsa::params::ml_dsa_44::*;
            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            // Verify determinism
            let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            // Verify key sizes
            assert_eq!(pk.len(), PK_BYTES, "ML-DSA-44 pk size mismatch");
            assert_eq!(sk.len(), SK_BYTES, "ML-DSA-44 sk size mismatch");
        }
        1 => {
            // ML-DSA-65
            use kylix_ml_dsa::params::ml_dsa_65::*;
            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            assert_eq!(pk.len(), PK_BYTES, "ML-DSA-65 pk size mismatch");
            assert_eq!(sk.len(), SK_BYTES, "ML-DSA-65 sk size mismatch");
        }
        _ => {
            // ML-DSA-87
            use kylix_ml_dsa::params::ml_dsa_87::*;
            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            let (sk2, pk2) = ml_dsa_keygen::<K, L, ETA>(&input.seed);
            assert_eq!(sk, sk2, "KeyGen should be deterministic");
            assert_eq!(pk, pk2, "KeyGen should be deterministic");
            assert_eq!(pk.len(), PK_BYTES, "ML-DSA-87 pk size mismatch");
            assert_eq!(sk.len(), SK_BYTES, "ML-DSA-87 sk size mismatch");
        }
    }
});
