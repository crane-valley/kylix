//! Property-based tests for ML-KEM using proptest.
//!
//! These tests verify fundamental cryptographic properties:
//! - Roundtrip: encaps followed by decaps recovers the shared secret
//! - Key sizes: Generated keys have correct sizes
//! - Ciphertext size: Ciphertexts have correct sizes
//! - Determinism: Same seed produces same keys

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing
fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary randomness for encapsulation
fn arb_randomness() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

#[cfg(feature = "ml-kem-512")]
mod ml_kem_512_props {
    use super::*;
    use kylix_ml_kem::Kem;
    use kylix_ml_kem::MlKem512;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Roundtrip property: encaps then decaps recovers the shared secret.
        #[test]
        fn roundtrip(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem512::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, ss_sender) = MlKem512::encaps(&ek, &mut encaps_rng).unwrap();

            let ss_receiver = MlKem512::decaps(&dk, &ct).unwrap();

            prop_assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem512::keygen(&mut rng).unwrap();

            prop_assert_eq!(dk.as_bytes().len(), MlKem512::DECAPSULATION_KEY_SIZE);
            prop_assert_eq!(ek.as_bytes().len(), MlKem512::ENCAPSULATION_KEY_SIZE);
        }

        /// Ciphertext size is correct.
        #[test]
        fn ciphertext_size(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (_, ek) = MlKem512::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, _) = MlKem512::encaps(&ek, &mut encaps_rng).unwrap();

            prop_assert_eq!(ct.as_bytes().len(), MlKem512::CIPHERTEXT_SIZE);
        }

        /// Determinism: same seed produces same keys.
        #[test]
        fn determinism(seed in arb_seed()) {
            let mut rng1 = StdRng::from_seed(seed);
            let mut rng2 = StdRng::from_seed(seed);

            let (dk1, ek1) = MlKem512::keygen(&mut rng1).unwrap();
            let (dk2, ek2) = MlKem512::keygen(&mut rng2).unwrap();

            prop_assert_eq!(dk1.as_bytes(), dk2.as_bytes());
            prop_assert_eq!(ek1.as_bytes(), ek2.as_bytes());
        }
    }
}

#[cfg(feature = "ml-kem-768")]
mod ml_kem_768_props {
    use super::*;
    use kylix_ml_kem::Kem;
    use kylix_ml_kem::MlKem768;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Roundtrip property: encaps then decaps recovers the shared secret.
        #[test]
        fn roundtrip(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem768::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, ss_sender) = MlKem768::encaps(&ek, &mut encaps_rng).unwrap();

            let ss_receiver = MlKem768::decaps(&dk, &ct).unwrap();

            prop_assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem768::keygen(&mut rng).unwrap();

            prop_assert_eq!(dk.as_bytes().len(), MlKem768::DECAPSULATION_KEY_SIZE);
            prop_assert_eq!(ek.as_bytes().len(), MlKem768::ENCAPSULATION_KEY_SIZE);
        }

        /// Ciphertext size is correct.
        #[test]
        fn ciphertext_size(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (_, ek) = MlKem768::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, _) = MlKem768::encaps(&ek, &mut encaps_rng).unwrap();

            prop_assert_eq!(ct.as_bytes().len(), MlKem768::CIPHERTEXT_SIZE);
        }

        /// Determinism: same seed produces same keys.
        #[test]
        fn determinism(seed in arb_seed()) {
            let mut rng1 = StdRng::from_seed(seed);
            let mut rng2 = StdRng::from_seed(seed);

            let (dk1, ek1) = MlKem768::keygen(&mut rng1).unwrap();
            let (dk2, ek2) = MlKem768::keygen(&mut rng2).unwrap();

            prop_assert_eq!(dk1.as_bytes(), dk2.as_bytes());
            prop_assert_eq!(ek1.as_bytes(), ek2.as_bytes());
        }
    }
}

#[cfg(feature = "ml-kem-1024")]
mod ml_kem_1024_props {
    use super::*;
    use kylix_ml_kem::Kem;
    use kylix_ml_kem::MlKem1024;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Roundtrip property: encaps then decaps recovers the shared secret.
        #[test]
        fn roundtrip(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem1024::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, ss_sender) = MlKem1024::encaps(&ek, &mut encaps_rng).unwrap();

            let ss_receiver = MlKem1024::decaps(&dk, &ct).unwrap();

            prop_assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
        }

        /// Key sizes are correct.
        #[test]
        fn key_sizes(seed in arb_seed()) {
            let mut rng = StdRng::from_seed(seed);
            let (dk, ek) = MlKem1024::keygen(&mut rng).unwrap();

            prop_assert_eq!(dk.as_bytes().len(), MlKem1024::DECAPSULATION_KEY_SIZE);
            prop_assert_eq!(ek.as_bytes().len(), MlKem1024::ENCAPSULATION_KEY_SIZE);
        }

        /// Ciphertext size is correct.
        #[test]
        fn ciphertext_size(seed in arb_seed(), enc_rand in arb_randomness()) {
            let mut keygen_rng = StdRng::from_seed(seed);
            let (_, ek) = MlKem1024::keygen(&mut keygen_rng).unwrap();

            let mut encaps_rng = StdRng::from_seed(enc_rand);
            let (ct, _) = MlKem1024::encaps(&ek, &mut encaps_rng).unwrap();

            prop_assert_eq!(ct.as_bytes().len(), MlKem1024::CIPHERTEXT_SIZE);
        }

        /// Determinism: same seed produces same keys.
        #[test]
        fn determinism(seed in arb_seed()) {
            let mut rng1 = StdRng::from_seed(seed);
            let mut rng2 = StdRng::from_seed(seed);

            let (dk1, ek1) = MlKem1024::keygen(&mut rng1).unwrap();
            let (dk2, ek2) = MlKem1024::keygen(&mut rng2).unwrap();

            prop_assert_eq!(dk1.as_bytes(), dk2.as_bytes());
            prop_assert_eq!(ek1.as_bytes(), ek2.as_bytes());
        }
    }
}
