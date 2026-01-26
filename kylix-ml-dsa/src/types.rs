//! Key type wrapper macros for ML-DSA.
//!
//! This module provides macros to generate the key type wrappers
//! (SigningKey, VerificationKey, Signature) for each ML-DSA variant.

/// Generate ML-DSA key types for a specific parameter set.
///
/// Creates SigningKey, VerificationKey, and Signature types
/// with the appropriate sizes and implementations.
macro_rules! define_dsa_types {
    (
        sk_size: $sk_size:expr,
        pk_size: $pk_size:expr,
        sig_size: $sig_size:expr,
        K: $K:expr,
        L: $L:expr
    ) => {
        /// Signing key (secret key).
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct SigningKey {
            bytes: [u8; $sk_size],
        }

        impl SigningKey {
            /// Create from bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $sk_size {
                    return Err(Error::InvalidKeyLength {
                        expected: $sk_size,
                        actual: bytes.len(),
                    });
                }
                let mut key = [0u8; $sk_size];
                key.copy_from_slice(bytes);
                Ok(Self { bytes: key })
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $sk_size] {
                &self.bytes
            }
        }

        /// Verification key (public key).
        #[derive(Clone)]
        pub struct VerificationKey {
            bytes: [u8; $pk_size],
        }

        impl VerificationKey {
            /// Create from bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $pk_size {
                    return Err(Error::InvalidKeyLength {
                        expected: $pk_size,
                        actual: bytes.len(),
                    });
                }
                let mut key = [0u8; $pk_size];
                key.copy_from_slice(bytes);
                Ok(Self { bytes: key })
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $pk_size] {
                &self.bytes
            }

            /// Expand the verification key for fast repeated verification.
            ///
            /// Pre-computes expensive values that would otherwise be recomputed
            /// on every `verify()` call:
            /// - Matrix A expansion from SHAKE128
            /// - t1 * 2^D in NTT domain
            /// - H(pk) hash
            ///
            /// # Example
            ///
            /// ```ignore
            /// // Expand the verification key once
            /// let expanded = pk.expand()?;
            ///
            /// // Verify multiple pre-existing signatures efficiently
            /// for (msg, sig) in messages_and_signatures {
            ///     MlDsa::verify_expanded(&expanded, msg, &sig)?;
            /// }
            /// ```
            pub fn expand(&self) -> Result<ExpandedVerificationKey> {
                expand_verification_key::<$K, $L>(self.as_bytes()).ok_or(Error::EncodingError)
            }
        }

        /// Expanded verification key with pre-computed values for fast repeated verification.
        pub type ExpandedVerificationKey = crate::sign::ExpandedVerificationKey<$K, $L>;

        /// Signature.
        #[derive(Clone)]
        pub struct Signature {
            bytes: [u8; $sig_size],
        }

        impl Signature {
            /// Create from bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != $sig_size {
                    return Err(Error::InvalidSignatureLength {
                        expected: $sig_size,
                        actual: bytes.len(),
                    });
                }
                let mut sig = [0u8; $sig_size];
                sig.copy_from_slice(bytes);
                Ok(Self { bytes: sig })
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $sig_size] {
                &self.bytes
            }
        }
    };
}

pub(crate) use define_dsa_types;
