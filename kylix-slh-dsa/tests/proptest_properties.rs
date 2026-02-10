// Helpers are used by feature-gated test modules; allow dead_code
// when compiling without variant features (e.g., --no-default-features).
#![cfg_attr(
    not(any(
        feature = "slh-dsa-shake-128s",
        feature = "slh-dsa-shake-128f",
        feature = "slh-dsa-shake-192s",
        feature = "slh-dsa-shake-192f",
        feature = "slh-dsa-shake-256s",
        feature = "slh-dsa-shake-256f",
        feature = "slh-dsa-sha2-128s",
        feature = "slh-dsa-sha2-128f",
        feature = "slh-dsa-sha2-192s",
        feature = "slh-dsa-sha2-192f",
        feature = "slh-dsa-sha2-256s",
        feature = "slh-dsa-sha2-256f",
    )),
    allow(dead_code)
)]

//! Property-based tests for SLH-DSA using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Basic properties: roundtrip (sign/verify), key sizes, signature size
//! - Wrong key: verification with wrong public key fails
//! - Tampered message: verification with tampered message fails
//!
//! Note: SLH-DSA is significantly slower than lattice-based schemes,
//! so we use fewer test cases (4-8 per property).

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary messages (0-128 bytes)
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..128)
}

macro_rules! slh_dsa_proptest {
    ($mod_name:ident, $variant:ident, $feature:literal, $cases:expr) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use super::*;
            use kylix_slh_dsa::Signer;
            use kylix_slh_dsa::$variant;
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
                fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..128) {
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

slh_dsa_proptest!(
    slh_dsa_shake_128f_props,
    SlhDsaShake128f,
    "slh-dsa-shake-128f",
    8
);
// 128s is very slow, use minimal cases
slh_dsa_proptest!(
    slh_dsa_shake_128s_props,
    SlhDsaShake128s,
    "slh-dsa-shake-128s",
    4
);
slh_dsa_proptest!(
    slh_dsa_shake_192f_props,
    SlhDsaShake192f,
    "slh-dsa-shake-192f",
    8
);
slh_dsa_proptest!(
    slh_dsa_shake_256f_props,
    SlhDsaShake256f,
    "slh-dsa-shake-256f",
    8
);
