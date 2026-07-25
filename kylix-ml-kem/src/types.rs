//! Key type wrapper macros for ML-KEM.
//!
//! This module provides macros to generate the key type wrappers
//! (DecapsulationKey, EncapsulationKey, Ciphertext, SharedSecret)
//! and the whole variant module (marker type, `Kem` impl, tests)
//! for each ML-KEM variant.

/// Generate ML-KEM key types for a specific parameter set.
///
/// Creates DecapsulationKey, EncapsulationKey, Ciphertext, and SharedSecret
/// types with the appropriate sizes and implementations.
macro_rules! define_kem_types {
    (
        dk_size: $dk_size:expr,
        ek_size: $ek_size:expr,
        ct_size: $ct_size:expr,
        ss_size: $ss_size:expr
    ) => {
        /// Decapsulation key (secret key).
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct DecapsulationKey {
            bytes: [u8; $dk_size],
        }

        ::kylix_core::impl_fixed_bytes!(
            for DecapsulationKey,
            size: $dk_size,
            error: InvalidKeyLength,
            as_bytes: &[u8]
        );

        /// Encapsulation key (public key).
        #[derive(Clone)]
        pub struct EncapsulationKey {
            bytes: [u8; $ek_size],
        }

        ::kylix_core::impl_fixed_bytes!(
            for EncapsulationKey,
            size: $ek_size,
            error: InvalidKeyLength,
            as_bytes: &[u8]
        );

        /// Ciphertext.
        #[derive(Clone)]
        pub struct Ciphertext {
            bytes: [u8; $ct_size],
        }

        ::kylix_core::impl_fixed_bytes!(
            for Ciphertext,
            size: $ct_size,
            error: InvalidCiphertextLength,
            as_bytes: &[u8]
        );

        /// Shared secret.
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct SharedSecret {
            bytes: [u8; $ss_size],
        }

        impl AsRef<[u8]> for SharedSecret {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
    };
}

pub(crate) use define_kem_types;

/// Generate a complete ML-KEM variant module for a specific parameter set.
///
/// Emits the key types (via [`define_kem_types`]), the algorithm marker struct,
/// its [`Kem`](kylix_core::Kem) implementation, and the shared variant test set.
/// The invoking module must import its parameter set (`use
/// crate::params::ml_kem_NNN::*;`) before the invocation.
///
/// The `*_size` arguments are the expected sizes asserted by the generated
/// tests; the implementation itself always reads the parameter constants, so a
/// mismatch between the two is a test failure rather than silent drift.
macro_rules! define_ml_kem_variant {
    (
        variant_doc: { $(#[$variant_doc:meta])* },
        variant_name: $variant_name:ident,
        dk_size: $dk_size:expr,
        ek_size: $ek_size:expr,
        ct_size: $ct_size:expr,
        ss_size: $ss_size:expr
    ) => {
        use crate::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};
        use kylix_core::{Kem, Result};
        use rand_core::CryptoRng;
        use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

        crate::types::define_kem_types! {
            dk_size: DECAPSULATION_KEY_SIZE,
            ek_size: ENCAPSULATION_KEY_SIZE,
            ct_size: CIPHERTEXT_SIZE,
            ss_size: SHARED_SECRET_SIZE
        }

        $(#[$variant_doc])*
        pub struct $variant_name;

        impl Kem for $variant_name {
            type DecapsulationKey = DecapsulationKey;
            type EncapsulationKey = EncapsulationKey;
            type Ciphertext = Ciphertext;
            type SharedSecret = SharedSecret;

            const DECAPSULATION_KEY_SIZE: usize = DECAPSULATION_KEY_SIZE;
            const ENCAPSULATION_KEY_SIZE: usize = ENCAPSULATION_KEY_SIZE;
            const CIPHERTEXT_SIZE: usize = CIPHERTEXT_SIZE;
            const SHARED_SECRET_SIZE: usize = SHARED_SECRET_SIZE;

            fn keygen(
                rng: &mut impl CryptoRng,
            ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey)> {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                rng.fill_bytes(&mut d);
                rng.fill_bytes(&mut z);

                let (dk_bytes, ek_bytes) = ml_kem_keygen::<K, ETA1>(&d, &z);
                let dk_bytes = Zeroizing::new(dk_bytes);

                // Zeroize seeds
                d.zeroize();
                z.zeroize();

                Ok((
                    DecapsulationKey::from_bytes(&dk_bytes)?,
                    EncapsulationKey::from_bytes(&ek_bytes)?,
                ))
            }

            fn encaps(
                ek: &Self::EncapsulationKey,
                rng: &mut impl CryptoRng,
            ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
                let mut m = Zeroizing::new([0u8; 32]);
                rng.fill_bytes(m.as_mut());

                let (ct_bytes, ss_bytes) =
                    ml_kem_encaps::<K, ETA1, ETA2, DU, DV>(ek.as_bytes(), &m)?;

                Ok((
                    Ciphertext::from_bytes(&ct_bytes)?,
                    SharedSecret { bytes: ss_bytes },
                ))
            }

            fn decaps(
                dk: &Self::DecapsulationKey,
                ct: &Self::Ciphertext,
            ) -> Result<Self::SharedSecret> {
                let ss_bytes =
                    ml_kem_decaps::<K, ETA1, ETA2, DU, DV>(dk.as_bytes(), ct.as_bytes())?;
                Ok(SharedSecret { bytes: ss_bytes })
            }
        }

        #[cfg(test)]
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        mod tests {
            use super::*;
            use kylix_core::Error;

            #[test]
            fn test_key_sizes() {
                assert_eq!($variant_name::DECAPSULATION_KEY_SIZE, $dk_size);
                assert_eq!($variant_name::ENCAPSULATION_KEY_SIZE, $ek_size);
                assert_eq!($variant_name::CIPHERTEXT_SIZE, $ct_size);
                assert_eq!($variant_name::SHARED_SECRET_SIZE, $ss_size);
            }

            #[test]
            fn test_encapsulation_key_from_bytes() {
                let bytes = [0u8; ENCAPSULATION_KEY_SIZE];
                let ek = EncapsulationKey::from_bytes(&bytes).unwrap();
                assert_eq!(ek.as_bytes(), &bytes);
            }

            #[test]
            fn test_encapsulation_key_invalid_length() {
                let bytes = [0u8; 100];
                let result = EncapsulationKey::from_bytes(&bytes);
                assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
            }

            #[test]
            fn test_roundtrip() {
                use rand::rng;

                let (dk, ek) = $variant_name::keygen(&mut rng()).unwrap();
                let (ct, ss_sender) = $variant_name::encaps(&ek, &mut rng()).unwrap();
                let ss_receiver = $variant_name::decaps(&dk, &ct).unwrap();

                assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
            }

            #[test]
            fn test_implicit_rejection() {
                use rand::rng;

                let (dk, ek) = $variant_name::keygen(&mut rng()).unwrap();
                let (ct, ss_sender) = $variant_name::encaps(&ek, &mut rng()).unwrap();

                // Corrupt ciphertext
                let mut ct_bytes = ct.as_bytes().to_vec();
                ct_bytes[0] ^= 0xFF;
                let ct_bad = Ciphertext::from_bytes(&ct_bytes).unwrap();

                // Decaps should succeed but return different key
                let ss_bad = $variant_name::decaps(&dk, &ct_bad).unwrap();
                assert_ne!(ss_sender.as_ref(), ss_bad.as_ref());
            }
        }
    };
}

pub(crate) use define_ml_kem_variant;
