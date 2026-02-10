// Skip compilation entirely when no variant features are enabled
// (e.g., --no-default-features), since all test functions are feature-gated.
#![cfg(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]

//! Property-based tests for ML-DSA using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Basic properties: roundtrip (sign/verify), key sizes, signature size
//! - Wrong key: verification with wrong public key fails
//! - Tampered message: verification with tampered message fails

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary messages (0-256 bytes)
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

macro_rules! ml_dsa_proptest {
    ($mod_name:ident, $variant:ident, $feature:literal, $cases:expr) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use super::*;
            use kylix_ml_dsa::$variant;
            use kylix_ml_dsa::Signer;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            proptest! {
                #![proptest_config(ProptestConfig::with_cases($cases))]

                /// Basic properties: roundtrip sign/verify, key sizes, signature size.
                #[test]
                fn basic_properties(seed in arb_seed(), message in arb_message()) {
                    let mut rng = StdRng::from_seed(seed);
                    let (sk, pk) = $variant::keygen(&mut rng).unwrap();

                    prop_assert_eq!(sk.as_bytes().len(), $variant::SIGNING_KEY_SIZE);
                    prop_assert_eq!(pk.as_bytes().len(), $variant::VERIFICATION_KEY_SIZE);

                    let sig = $variant::sign(&sk, &message).unwrap();
                    prop_assert_eq!(sig.as_bytes().len(), $variant::SIGNATURE_SIZE);

                    prop_assert!($variant::verify(&pk, &message, &sig).is_ok());
                }

                /// Verification with wrong public key fails.
                #[test]
                fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
                    prop_assume!(seed1 != seed2);

                    let mut rng1 = StdRng::from_seed(seed1);
                    let mut rng2 = StdRng::from_seed(seed2);

                    let (sk1, _pk1) = $variant::keygen(&mut rng1).unwrap();
                    let (_sk2, pk2) = $variant::keygen(&mut rng2).unwrap();

                    let sig = $variant::sign(&sk1, &message).unwrap();
                    prop_assert!($variant::verify(&pk2, &message, &sig).is_err());
                }

                /// Verification with tampered message fails.
                #[test]
                fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..256) {
                    prop_assume!(!message.is_empty());

                    let mut rng = StdRng::from_seed(seed);
                    let (sk, pk) = $variant::keygen(&mut rng).unwrap();

                    let sig = $variant::sign(&sk, &message).unwrap();

                    let mut tampered = message.clone();
                    let pos = flip_pos % tampered.len();
                    tampered[pos] ^= 0xFF;

                    prop_assert!($variant::verify(&pk, &tampered, &sig).is_err());
                }
            }
        }
    };
}

ml_dsa_proptest!(ml_dsa_44_props, MlDsa44, "ml-dsa-44", 16);
ml_dsa_proptest!(ml_dsa_65_props, MlDsa65, "ml-dsa-65", 16);
ml_dsa_proptest!(ml_dsa_87_props, MlDsa87, "ml-dsa-87", 16);
