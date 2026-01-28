//! Property-based tests for ML-DSA using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Roundtrip: sign followed by verify succeeds
//! - Key sizes: Generated keys have correct sizes
//! - Signature size: Signatures have correct sizes
//! - Wrong key: Verification with wrong public key fails
//! - Tampered message: Verification with tampered message fails

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary messages (0-256 bytes)
fn arb_message() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

#[cfg(feature = "ml-dsa-44")]
mod ml_dsa_44_props {
    use super::*;
    use kylix_ml_dsa::MlDsa44;
    use kylix_ml_dsa::Signer;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa44::keygen(&mut rng).unwrap();

            let sig = MlDsa44::sign(&sk, &message).unwrap();
            prop_assert!(MlDsa44::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa44::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.as_bytes().len(), MlDsa44::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.as_bytes().len(), MlDsa44::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = MlDsa44::keygen(&mut rng).unwrap();

            let sig = MlDsa44::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.as_bytes().len(), MlDsa44::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = MlDsa44::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = MlDsa44::keygen(&mut rng2).unwrap();

            let sig = MlDsa44::sign(&sk1, &message).unwrap();
            prop_assert!(MlDsa44::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..256) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa44::keygen(&mut rng).unwrap();

            let sig = MlDsa44::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(MlDsa44::verify(&pk, &tampered, &sig).is_err());
        }
    }
}

#[cfg(feature = "ml-dsa-65")]
mod ml_dsa_65_props {
    use super::*;
    use kylix_ml_dsa::MlDsa65;
    use kylix_ml_dsa::Signer;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

            let sig = MlDsa65::sign(&sk, &message).unwrap();
            prop_assert!(MlDsa65::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.as_bytes().len(), MlDsa65::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.as_bytes().len(), MlDsa65::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = MlDsa65::keygen(&mut rng).unwrap();

            let sig = MlDsa65::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.as_bytes().len(), MlDsa65::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = MlDsa65::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = MlDsa65::keygen(&mut rng2).unwrap();

            let sig = MlDsa65::sign(&sk1, &message).unwrap();
            prop_assert!(MlDsa65::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..256) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

            let sig = MlDsa65::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(MlDsa65::verify(&pk, &tampered, &sig).is_err());
        }
    }
}

#[cfg(feature = "ml-dsa-87")]
mod ml_dsa_87_props {
    use super::*;
    use kylix_ml_dsa::MlDsa87;
    use kylix_ml_dsa::Signer;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa87::keygen(&mut rng).unwrap();

            let sig = MlDsa87::sign(&sk, &message).unwrap();
            prop_assert!(MlDsa87::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa87::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.as_bytes().len(), MlDsa87::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.as_bytes().len(), MlDsa87::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = MlDsa87::keygen(&mut rng).unwrap();

            let sig = MlDsa87::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.as_bytes().len(), MlDsa87::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = MlDsa87::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = MlDsa87::keygen(&mut rng2).unwrap();

            let sig = MlDsa87::sign(&sk1, &message).unwrap();
            prop_assert!(MlDsa87::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..256) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = MlDsa87::keygen(&mut rng).unwrap();

            let sig = MlDsa87::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(MlDsa87::verify(&pk, &tampered, &sig).is_err());
        }
    }
}
