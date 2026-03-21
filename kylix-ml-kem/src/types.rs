//! Key type wrapper macros for ML-KEM.
//!
//! This module provides macros to generate the key type wrappers
//! (DecapsulationKey, EncapsulationKey, Ciphertext, SharedSecret)
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
