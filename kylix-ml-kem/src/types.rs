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

        impl DecapsulationKey {
            /// Create a decapsulation key from bytes.
            ///
            /// Writes directly into the struct to avoid intermediate buffers
            /// that could leave sensitive data on the stack.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $dk_size {
                    return Err(Error::InvalidKeyLength {
                        expected: $dk_size,
                        actual: bytes.len(),
                    });
                }
                let mut result = Self {
                    bytes: [0u8; $dk_size],
                };
                result.bytes.copy_from_slice(bytes);
                Ok(result)
            }

            /// Get the key as a byte slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        /// Encapsulation key (public key).
        #[derive(Clone)]
        pub struct EncapsulationKey {
            bytes: [u8; $ek_size],
        }

        impl EncapsulationKey {
            /// Create an encapsulation key from bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $ek_size {
                    return Err(Error::InvalidKeyLength {
                        expected: $ek_size,
                        actual: bytes.len(),
                    });
                }
                let mut result = Self {
                    bytes: [0u8; $ek_size],
                };
                result.bytes.copy_from_slice(bytes);
                Ok(result)
            }

            /// Get the key as a byte slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        /// Ciphertext.
        #[derive(Clone)]
        pub struct Ciphertext {
            bytes: [u8; $ct_size],
        }

        impl Ciphertext {
            /// Create a ciphertext from bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $ct_size {
                    return Err(Error::InvalidCiphertextLength {
                        expected: $ct_size,
                        actual: bytes.len(),
                    });
                }
                let mut result = Self {
                    bytes: [0u8; $ct_size],
                };
                result.bytes.copy_from_slice(bytes);
                Ok(result)
            }

            /// Get the ciphertext as a byte slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

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
