//! Key type wrapper macros for SLH-DSA.
//!
//! This module provides macros to generate the key type wrappers
//! (SigningKey, VerificationKey, Signature) and Signer implementation
//! for each SLH-DSA variant.

/// Generate SLH-DSA types and Signer implementation for a specific parameter set.
///
/// Creates SigningKey, VerificationKey, Signature types and implements
/// the Signer trait for the variant marker type.
///
/// The key types use fixed-size byte arrays for consistent API with ML-KEM/ML-DSA:
/// - `SigningKey`: `[u8; SK_BYTES]` with automatic zeroization
/// - `VerificationKey`: `[u8; PK_BYTES]`
/// - `Signature`: `Vec<u8>` (heap-allocated due to large size, up to 49KB)
macro_rules! define_slh_dsa_variant {
    (
        variant_name: $variant_name:ident,
        hash_type: $hash_type:ty,
        sk_size: $sk_size:expr,
        pk_size: $pk_size:expr,
        sig_size: $sig_size:expr
    ) => {
        extern crate alloc;
        use crate::sign::{slh_keygen, slh_sign, slh_verify, PublicKey, SecretKey};
        use alloc::vec::Vec;

        use kylix_core::{Error, Result, Signer};
        use rand_core::CryptoRng;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        /// Signing key (secret key).
        ///
        /// Stores the key as a fixed-size byte array. Secret material is
        /// automatically zeroized when dropped.
        pub struct SigningKey {
            bytes: [u8; SK_BYTES],
        }

        impl SigningKey {
            /// Create a signing key from bytes.
            ///
            /// Returns an error if the slice length doesn't match the expected key size.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                // Use try_into for conversion; zeroize the intermediate buffer
                // to prevent secret material from lingering on the stack
                let mut sk_bytes: [u8; SK_BYTES] =
                    bytes.try_into().map_err(|_| Error::InvalidKeyLength {
                        expected: SK_BYTES,
                        actual: bytes.len(),
                    })?;
                let key = Self { bytes: sk_bytes };
                sk_bytes.zeroize();
                Ok(key)
            }

            /// Get the signing key bytes as a slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }

            /// Get the corresponding verification key.
            pub fn verification_key(&self) -> VerificationKey {
                // Extract pk_seed and pk_root from bytes
                // Layout: sk_seed || sk_prf || pk_seed || pk_root
                let mut pk_bytes = [0u8; PK_BYTES];
                pk_bytes.copy_from_slice(&self.bytes[2 * N..]);
                VerificationKey { bytes: pk_bytes }
            }
        }

        impl Clone for SigningKey {
            fn clone(&self) -> Self {
                Self { bytes: self.bytes }
            }
        }

        impl Zeroize for SigningKey {
            fn zeroize(&mut self) {
                self.bytes.zeroize();
            }
        }

        impl ZeroizeOnDrop for SigningKey {}

        impl Drop for SigningKey {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        /// Verification key (public key).
        ///
        /// Stores the key as a fixed-size byte array.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct VerificationKey {
            bytes: [u8; PK_BYTES],
        }

        impl VerificationKey {
            /// Create a verification key from bytes.
            ///
            /// Returns an error if the slice length doesn't match the expected key size.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let bytes: [u8; PK_BYTES] =
                    bytes.try_into().map_err(|_| Error::InvalidKeyLength {
                        expected: PK_BYTES,
                        actual: bytes.len(),
                    })?;
                Ok(Self { bytes })
            }

            /// Get the verification key bytes as a slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        /// Signature.
        ///
        /// Stores the signature as a heap-allocated byte vector.
        /// SLH-DSA signatures can be up to 49KB, too large for stack allocation.
        #[derive(Clone, PartialEq, Eq)]
        pub struct Signature(Vec<u8>);

        impl Signature {
            /// Create a signature from bytes.
            ///
            /// Returns an error if the slice length doesn't match the expected signature size.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                if bytes.len() != SIG_BYTES {
                    return Err(Error::InvalidSignatureLength {
                        expected: SIG_BYTES,
                        actual: bytes.len(),
                    });
                }
                Ok(Self(bytes.to_vec()))
            }

            /// Get the signature bytes as a slice.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8]> for Signature {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl core::fmt::Debug for Signature {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Only show first 32 bytes to avoid huge output
                write!(f, "Signature({:02x?}...)", &self.0[..32.min(SIG_BYTES)])
            }
        }

        /// Algorithm marker type.
        pub struct $variant_name;

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
                let (sk, pk) = slh_keygen::<$hash_type, N, WOTS_LEN, H_PRIME, D>(rng);

                // Write directly to fixed-size arrays (no heap allocation)
                let mut sk_bytes = [0u8; SK_BYTES];
                let mut pk_bytes = [0u8; PK_BYTES];
                sk.write_to(&mut sk_bytes);
                pk.write_to(&mut pk_bytes);

                let signing_key = SigningKey { bytes: sk_bytes };
                // Zeroize temporary buffer to prevent secret material from lingering on stack
                sk_bytes.zeroize();

                Ok((signing_key, VerificationKey { bytes: pk_bytes }))
            }

            fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
                // Convert bytes back to SecretKey for signing
                // This conversion is infallible since sk.bytes has the correct fixed size
                let secret_key = SecretKey::<N>::from_bytes(&sk.bytes)
                    .expect("infallible: SigningKey has correct size");

                let sig_vec =
                    slh_sign::<$hash_type, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
                        &secret_key,
                        message,
                        None,
                    );

                Ok(Signature(sig_vec))
            }

            fn verify(
                pk: &Self::VerificationKey,
                message: &[u8],
                signature: &Self::Signature,
            ) -> Result<()> {
                // Convert bytes back to PublicKey for verification
                // This conversion is infallible since pk.bytes has the correct fixed size
                let public_key = PublicKey::<N>::from_bytes(&pk.bytes)
                    .expect("infallible: VerificationKey has correct size");

                if slh_verify::<$hash_type, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                    &public_key,
                    message,
                    &signature.0,
                ) {
                    Ok(())
                } else {
                    Err(Error::VerificationFailed)
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            #[test]
            fn test_keygen_sign_verify() {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let message = b"Hello, SLH-DSA!";
                let signature = $variant_name::sign(&sk, message).unwrap();

                assert!($variant_name::verify(&pk, message, &signature).is_ok());
            }

            #[test]
            fn test_key_sizes() {
                assert_eq!($variant_name::SIGNING_KEY_SIZE, $sk_size);
                assert_eq!($variant_name::VERIFICATION_KEY_SIZE, $pk_size);
                assert_eq!($variant_name::SIGNATURE_SIZE, $sig_size);
            }

            #[test]
            fn test_key_serialization() {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let sk_bytes = sk.as_bytes();
                let sk_restored = SigningKey::from_bytes(sk_bytes).unwrap();
                assert_eq!(sk.verification_key(), sk_restored.verification_key());

                let pk_bytes = pk.as_bytes();
                let pk_restored = VerificationKey::from_bytes(pk_bytes).unwrap();
                assert_eq!(pk, pk_restored);
            }

            #[test]
            fn test_signature_size() {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let (sk, _pk) = $variant_name::keygen(&mut rng).unwrap();

                let message = b"Test message";
                let signature = $variant_name::sign(&sk, message).unwrap();

                assert_eq!(signature.as_bytes().len(), SIG_BYTES);
            }

            #[test]
            fn test_wrong_message_fails() {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let (sk, pk) = $variant_name::keygen(&mut rng).unwrap();

                let message = b"Original message";
                let signature = $variant_name::sign(&sk, message).unwrap();

                let wrong_message = b"Wrong message";
                assert!($variant_name::verify(&pk, wrong_message, &signature).is_err());
            }
        }
    };
}

pub(crate) use define_slh_dsa_variant;
