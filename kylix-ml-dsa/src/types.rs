//! Key type wrapper macros for ML-DSA.
//!
//! This module provides macros to generate the key type wrappers
//! (SigningKey, VerificationKey, Signature) and the whole variant
//! module (marker type, `Signer` impl, tests) for each ML-DSA variant.

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
            as_bytes: &[u8]
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
            as_bytes: &[u8]
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
            as_bytes: &[u8]
        );
    };
}

pub(crate) use define_dsa_types;

/// Generate a complete ML-DSA variant module for a specific parameter set.
///
/// Emits the algorithm marker struct, the key types (via [`define_dsa_types`]),
/// the `Signer` implementation, the inherent `verify_expanded` method, and the
/// shared variant test set. The invoking module must import its parameter set
/// (`use crate::params::ml_dsa_NN::*;`) before the invocation.
///
/// The `*_size` arguments are the expected sizes asserted by the generated
/// tests; the implementation itself always reads the parameter constants, so a
/// mismatch between the two is a test failure rather than silent drift.
macro_rules! define_ml_dsa_variant {
    (
        marker_doc: { $(#[$marker_doc:meta])* },
        variant_name: $variant_name:ident,
        verify_expanded_doc: { $(#[$verify_expanded_doc:meta])* },
        sk_size: $sk_size:expr,
        pk_size: $pk_size:expr,
        sig_size: $sig_size:expr,
        message: $message:expr
    ) => {
        use crate::sign::{
            expand_verification_key, ml_dsa_keygen, ml_dsa_sign_with_prefix,
            ml_dsa_verify_expanded_with_prefix, ml_dsa_verify_with_prefix,
        };
        use kylix_core::{Error, Result, Signer};
        use rand_core::CryptoRng;
        use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

        $(#[$marker_doc])*
        pub struct $variant_name;

        crate::types::define_dsa_types! {
            sk_size: SK_BYTES,
            pk_size: PK_BYTES,
            sig_size: SIG_BYTES,
            K: K,
            L: L
        }

        impl Signer for $variant_name {
            type SigningKey = SigningKey;
            type VerificationKey = VerificationKey;
            type Signature = Signature;

            const SIGNING_KEY_SIZE: usize = SK_BYTES;
            const VERIFICATION_KEY_SIZE: usize = PK_BYTES;
            const SIGNATURE_SIZE: usize = SIG_BYTES;

            fn keygen(
                rng: &mut impl CryptoRng,
            ) -> Result<(Self::SigningKey, Self::VerificationKey)> {
                let mut xi = [0u8; 32];
                rng.fill_bytes(&mut xi);

                let (sk_bytes, pk_bytes) = ml_dsa_keygen::<K, L, ETA>(&xi);
                let sk_bytes = Zeroizing::new(sk_bytes);

                xi.zeroize();

                let sk = SigningKey::from_bytes(&sk_bytes)?;

                let pk = VerificationKey::from_bytes(&pk_bytes)?;

                Ok((sk, pk))
            }

            fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
                // Use deterministic signing (rnd = 0)
                let rnd = [0u8; 32];
                let sig_bytes = ml_dsa_sign_with_prefix::<
                    K,
                    L,
                    ETA,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(sk.as_bytes(), &[0, 0], message, &rnd)
                .ok_or(Error::EncodingError)?;

                Signature::from_bytes(&sig_bytes)
            }

            fn verify(
                pk: &Self::VerificationKey,
                message: &[u8],
                signature: &Self::Signature,
            ) -> Result<()> {
                let valid = ml_dsa_verify_with_prefix::<
                    K,
                    L,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(pk.as_bytes(), &[0, 0], message, signature.as_bytes());

                if valid {
                    Ok(())
                } else {
                    Err(Error::VerificationFailed)
                }
            }
        }

        impl $variant_name {
            $(#[$verify_expanded_doc])*
            pub fn verify_expanded(
                expanded: &ExpandedVerificationKey,
                message: &[u8],
                signature: &Signature,
            ) -> Result<()> {
                let valid = ml_dsa_verify_expanded_with_prefix::<
                    K,
                    L,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(expanded, &[0, 0], message, signature.as_bytes());

                if valid {
                    Ok(())
                } else {
                    Err(Error::VerificationFailed)
                }
            }
        }

        #[cfg(test)]
        #[allow(clippy::unwrap_used, clippy::expect_used)]
        mod tests {
            use super::*;
            use crate::sign::ml_dsa_verify;

            #[test]
            fn test_key_sizes() {
                assert_eq!($variant_name::SIGNING_KEY_SIZE, $sk_size);
                assert_eq!($variant_name::VERIFICATION_KEY_SIZE, $pk_size);
                assert_eq!($variant_name::SIGNATURE_SIZE, $sig_size);
            }

            #[test]
            fn test_keygen() {
                let mut rng = rand::rng();
                let result = $variant_name::keygen(&mut rng);
                assert!(result.is_ok());

                let (sk, pk) = result.unwrap();
                assert_eq!(sk.as_bytes().len(), SK_BYTES);
                assert_eq!(pk.as_bytes().len(), PK_BYTES);
            }

            #[test]
            fn test_roundtrip() {
                let mut rng = rand::rng();
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let message = $message;
                let signature = $variant_name::sign(&sk, message).unwrap();

                assert_eq!(signature.as_bytes().len(), SIG_BYTES);

                let result = $variant_name::verify(&pk, message, &signature);
                assert!(result.is_ok(), "Verification failed: {:?}", result);
            }

            #[test]
            fn test_signer_uses_pure_ml_dsa_domain_separation() {
                let mut rng = rand::rng();
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();
                let message = b"domain-separated message";
                let signature = $variant_name::sign(&sk, message).unwrap();

                let mut pure_message = Vec::with_capacity(message.len() + 2);
                pure_message.extend_from_slice(&[0, 0]);
                pure_message.extend_from_slice(message);

                let raw_valid =
                    ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                        pk.as_bytes(),
                        message,
                        signature.as_bytes(),
                    );
                let pure_valid =
                    ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                        pk.as_bytes(),
                        &pure_message,
                        signature.as_bytes(),
                    );

                assert!(!raw_valid);
                assert!(pure_valid);
            }

            #[test]
            fn test_expanded_verify() {
                let mut rng = rand::rng();
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let expanded = pk.expand().expect("expand should succeed");

                let message = b"Test expanded verification";
                let signature = $variant_name::sign(&sk, message).unwrap();

                // Expanded verify should succeed
                let result = $variant_name::verify_expanded(&expanded, message, &signature);
                assert!(result.is_ok(), "Expanded verification failed: {:?}", result);

                // Regular verify should also succeed
                let result = $variant_name::verify(&pk, message, &signature);
                assert!(result.is_ok(), "Regular verification failed: {:?}", result);
            }

            #[test]
            fn test_expanded_verify_wrong_message() {
                let mut rng = rand::rng();
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let expanded = pk.expand().expect("expand should succeed");

                let message = b"Original message";
                let wrong_message = b"Wrong message";
                let signature = $variant_name::sign(&sk, message).unwrap();

                // Should fail with wrong message
                let result = $variant_name::verify_expanded(&expanded, wrong_message, &signature);
                assert!(result.is_err(), "Should fail with wrong message");
            }

            #[test]
            fn test_expanded_verify_multiple_signatures() {
                let mut rng = rand::rng();
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let expanded = pk.expand().expect("expand should succeed");

                // Verify multiple signatures with the same expanded key
                for i in 0..5 {
                    let message = format!("Message number {}", i);
                    let signature = $variant_name::sign(&sk, message.as_bytes()).unwrap();
                    let result =
                        $variant_name::verify_expanded(&expanded, message.as_bytes(), &signature);
                    assert!(result.is_ok(), "Verification {} failed: {:?}", i, result);
                }
            }
        }
    };
}

pub(crate) use define_ml_dsa_variant;
