// Skip compilation entirely when no variant features are enabled
// (e.g., --no-default-features), since all test functions are feature-gated.
#![cfg(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
))]

//! Property-based tests for ML-KEM using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Basic properties: roundtrip (encaps/decaps), key sizes, ciphertext size
//! - Determinism: same seed produces same keys

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary randomness for encapsulation
fn arb_randomness() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

macro_rules! ml_kem_proptest {
    ($mod_name:ident, $variant:ident, $feature:literal, $cases:expr) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use super::*;
            use kylix_ml_kem::$variant;
            use kylix_ml_kem::Kem;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases($cases))]

                /// Basic properties: roundtrip encaps/decaps, key sizes, ciphertext size.
                #[test]
                fn basic_properties(seed in arb_seed(), enc_rand in arb_randomness()) {
                    let mut keygen_rng = StdRng::from_seed(seed);
                    let (dk, ek) = $variant::keygen(&mut keygen_rng).unwrap();

                    prop_assert_eq!(dk.as_bytes().len(), $variant::DECAPSULATION_KEY_SIZE);
                    prop_assert_eq!(ek.as_bytes().len(), $variant::ENCAPSULATION_KEY_SIZE);

                    let mut encaps_rng = StdRng::from_seed(enc_rand);
                    let (ct, ss_sender) = $variant::encaps(&ek, &mut encaps_rng).unwrap();

                    prop_assert_eq!(ct.as_bytes().len(), $variant::CIPHERTEXT_SIZE);

                    let ss_receiver = $variant::decaps(&dk, &ct).unwrap();
                    prop_assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
                }

                /// Determinism: same seed produces same keys.
                #[test]
                fn determinism(seed in arb_seed()) {
                    let mut rng1 = StdRng::from_seed(seed);
                    let mut rng2 = StdRng::from_seed(seed);

                    let (dk1, ek1) = $variant::keygen(&mut rng1).unwrap();
                    let (dk2, ek2) = $variant::keygen(&mut rng2).unwrap();

                    prop_assert_eq!(dk1.as_bytes(), dk2.as_bytes());
                    prop_assert_eq!(ek1.as_bytes(), ek2.as_bytes());
                }
            }
        }
    };
}

ml_kem_proptest!(ml_kem_512_props, MlKem512, "ml-kem-512", 32);
ml_kem_proptest!(ml_kem_768_props, MlKem768, "ml-kem-768", 32);
ml_kem_proptest!(ml_kem_1024_props, MlKem1024, "ml-kem-1024", 32);
