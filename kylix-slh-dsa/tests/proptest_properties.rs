//! Property-based tests for SLH-DSA using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Roundtrip: sign followed by verify succeeds
//! - Key sizes: Generated keys have correct sizes
//! - Signature size: Signatures have correct sizes
//! - Wrong key: Verification with wrong public key fails
//! - Tampered message: Verification with tampered message fails
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

#[cfg(feature = "slh-dsa-shake-128f")]
mod slh_dsa_shake_128f_props {
    use super::*;
    use kylix_slh_dsa::Signer;
    use kylix_slh_dsa::SlhDsaShake128f;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128f::sign(&sk, &message).unwrap();
            prop_assert!(SlhDsaShake128f::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.to_bytes().len(), SlhDsaShake128f::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.to_bytes().len(), SlhDsaShake128f::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = SlhDsaShake128f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128f::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.to_bytes().len(), SlhDsaShake128f::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = SlhDsaShake128f::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = SlhDsaShake128f::keygen(&mut rng2).unwrap();

            let sig = SlhDsaShake128f::sign(&sk1, &message).unwrap();
            prop_assert!(SlhDsaShake128f::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..128) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128f::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(SlhDsaShake128f::verify(&pk, &tampered, &sig).is_err());
        }
    }
}

#[cfg(feature = "slh-dsa-shake-128s")]
mod slh_dsa_shake_128s_props {
    use super::*;
    use kylix_slh_dsa::Signer;
    use kylix_slh_dsa::SlhDsaShake128s;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        // 128s is very slow, use minimal cases
        #![proptest_config(ProptestConfig::with_cases(4))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128s::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128s::sign(&sk, &message).unwrap();
            prop_assert!(SlhDsaShake128s::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128s::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.to_bytes().len(), SlhDsaShake128s::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.to_bytes().len(), SlhDsaShake128s::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = SlhDsaShake128s::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128s::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.to_bytes().len(), SlhDsaShake128s::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = SlhDsaShake128s::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = SlhDsaShake128s::keygen(&mut rng2).unwrap();

            let sig = SlhDsaShake128s::sign(&sk1, &message).unwrap();
            prop_assert!(SlhDsaShake128s::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..128) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake128s::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake128s::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(SlhDsaShake128s::verify(&pk, &tampered, &sig).is_err());
        }
    }
}

#[cfg(feature = "slh-dsa-shake-192f")]
mod slh_dsa_shake_192f_props {
    use super::*;
    use kylix_slh_dsa::Signer;
    use kylix_slh_dsa::SlhDsaShake192f;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake192f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake192f::sign(&sk, &message).unwrap();
            prop_assert!(SlhDsaShake192f::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake192f::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.to_bytes().len(), SlhDsaShake192f::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.to_bytes().len(), SlhDsaShake192f::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = SlhDsaShake192f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake192f::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.to_bytes().len(), SlhDsaShake192f::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = SlhDsaShake192f::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = SlhDsaShake192f::keygen(&mut rng2).unwrap();

            let sig = SlhDsaShake192f::sign(&sk1, &message).unwrap();
            prop_assert!(SlhDsaShake192f::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..128) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake192f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake192f::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(SlhDsaShake192f::verify(&pk, &tampered, &sig).is_err());
        }
    }
}

#[cfg(feature = "slh-dsa-shake-256f")]
mod slh_dsa_shake_256f_props {
    use super::*;
    use kylix_slh_dsa::Signer;
    use kylix_slh_dsa::SlhDsaShake256f;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Roundtrip property: sign then verify succeeds.
        #[test]
        fn roundtrip(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake256f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake256f::sign(&sk, &message).unwrap();
            prop_assert!(SlhDsaShake256f::verify(&pk, &message, &sig).is_ok());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake256f::keygen(&mut rng).unwrap();

            prop_assert_eq!(sk.to_bytes().len(), SlhDsaShake256f::SIGNING_KEY_SIZE);
            prop_assert_eq!(pk.to_bytes().len(), SlhDsaShake256f::VERIFICATION_KEY_SIZE);
        }

        /// Signature size is correct.
        #[test]
        fn signature_size(seed in arb_seed(), message in arb_message()) {
            let mut rng = StdRng::from_seed(seed);
            let (sk, _) = SlhDsaShake256f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake256f::sign(&sk, &message).unwrap();
            prop_assert_eq!(sig.to_bytes().len(), SlhDsaShake256f::SIGNATURE_SIZE);
        }

        /// Verification with wrong public key fails.
        #[test]
        fn wrong_key_fails(seed1 in arb_seed(), seed2 in arb_seed(), message in arb_message()) {
            // Skip if seeds are identical
            prop_assume!(seed1 != seed2);

            let mut rng1 = StdRng::from_seed(seed1);
            let mut rng2 = StdRng::from_seed(seed2);

            let (sk1, _pk1) = SlhDsaShake256f::keygen(&mut rng1).unwrap();
            let (_sk2, pk2) = SlhDsaShake256f::keygen(&mut rng2).unwrap();

            let sig = SlhDsaShake256f::sign(&sk1, &message).unwrap();
            prop_assert!(SlhDsaShake256f::verify(&pk2, &message, &sig).is_err());
        }

        /// Verification with tampered message fails.
        #[test]
        fn tampered_message_fails(seed in arb_seed(), message in arb_message(), flip_pos in 0usize..128) {
            // Need non-empty message to tamper
            prop_assume!(!message.is_empty());

            let mut rng = StdRng::from_seed(seed);
            let (sk, pk) = SlhDsaShake256f::keygen(&mut rng).unwrap();

            let sig = SlhDsaShake256f::sign(&sk, &message).unwrap();

            // Tamper with the message
            let mut tampered = message.clone();
            let pos = flip_pos % tampered.len();
            tampered[pos] ^= 0xFF;

            prop_assert!(SlhDsaShake256f::verify(&pk, &tampered, &sig).is_err());
        }
    }
}
