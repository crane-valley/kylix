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

        ::kylix_core::impl_fixed_bytes!(
            for SigningKey,
            size: $sk_size,
            error: InvalidKeyLength,
            as_bytes: &[u8; $sk_size]
        );

        /// Verification key (public key).
        #[derive(Clone)]
        pub struct VerificationKey {
            bytes: [u8; $pk_size],
        }

        impl VerificationKey {
            /// Expand the verification key for fast repeated verification.
            ///
            /// Pre-computes expensive values that would otherwise be recomputed
            /// on every `verify()` call:
            /// - Matrix A expansion from SHAKE128
            /// - t1 * 2^D in NTT domain
            /// - H(pk) hash
            ///
            /// This is faster than regular `verify()` when verifying multiple
            /// signatures with the same public key.
            ///
            /// # Performance (ML-DSA-65)
            ///
            /// | Method | Time per verify |
            /// |--------|-----------------|
            /// | `verify()` | ~101 µs |
            /// | `verify_expanded()` | ~38 µs |
            /// | `expand()` (one-time) | ~68 µs |
            ///
            /// Break-even: 2 verifications with the same key.
            ///
            /// # Example
            ///
            /// ```ignore
            /// // Expand the verification key once
            /// let expanded = pk.expand()?;
            ///
            /// // Verify multiple (message, signature) pairs efficiently
            /// // Replace MlDsa65 with MlDsa44 or MlDsa87 as appropriate
            /// for (message, signature) in messages_and_signatures {
            ///     MlDsa65::verify_expanded(&expanded, message, &signature)?;
            /// }
            /// ```
            pub fn expand(&self) -> Result<ExpandedVerificationKey> {
                expand_verification_key::<$K, $L>(self.as_bytes()).ok_or(Error::EncodingError)
            }
        }

        ::kylix_core::impl_fixed_bytes!(
            for VerificationKey,
            size: $pk_size,
            error: InvalidKeyLength,
            as_bytes: &[u8; $pk_size]
        );

        /// Expanded verification key with pre-computed values for fast repeated verification.
        ///
        /// See [`VerificationKey::expand`] for usage and performance details.
        pub type ExpandedVerificationKey = crate::sign::ExpandedVerificationKey<$K, $L>;

        /// Signature.
        #[derive(Clone)]
        pub struct Signature {
            bytes: [u8; $sig_size],
        }

        ::kylix_core::impl_fixed_bytes!(
            for Signature,
            size: $sig_size,
            error: InvalidSignatureLength,
            as_bytes: &[u8; $sig_size]
        );
    };
}

pub(crate) use define_dsa_types;
