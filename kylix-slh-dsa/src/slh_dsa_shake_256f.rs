//! SLH-DSA-SHAKE-256f implementation.
//!
//! Fast variant with 256-bit security using SHAKE256.
//! Signature size: 49,856 bytes

use crate::hash_shake::Shake256Hash;
use crate::params::slh_dsa_shake_256f::*;
use crate::sign::{slh_keygen, slh_sign, slh_verify, PublicKey, SecretKey};

use kylix_core::{Error, Result, Signer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// SLH-DSA-SHAKE-256f signing key.
pub struct SigningKey(SecretKey<N>);

impl SigningKey {
    /// Create a signing key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        SecretKey::from_bytes(bytes).map(Self)
    }

    /// Serialize the signing key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Get the corresponding verification key.
    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey(PublicKey {
            pk_seed: self.0.pk_seed,
            pk_root: self.0.pk_root,
        })
    }
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.0.sk_seed.zeroize();
        self.0.sk_prf.zeroize();
    }
}

impl ZeroizeOnDrop for SigningKey {}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SLH-DSA-SHAKE-256f verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey(PublicKey<N>);

impl VerificationKey {
    /// Create a verification key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        PublicKey::from_bytes(bytes).map(Self)
    }

    /// Serialize the verification key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

/// SLH-DSA-SHAKE-256f signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIG_BYTES {
            return None;
        }
        Some(Self(bytes.to_vec()))
    }

    /// Get the signature bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// SLH-DSA-SHAKE-256f algorithm marker type.
pub struct SlhDsaShake256f;

impl Signer for SlhDsaShake256f {
    type SigningKey = SigningKey;
    type VerificationKey = VerificationKey;
    type Signature = Signature;

    const SIGNING_KEY_SIZE: usize = SK_BYTES;
    const VERIFICATION_KEY_SIZE: usize = PK_BYTES;
    const SIGNATURE_SIZE: usize = SIG_BYTES;

    fn keygen(rng: &mut impl CryptoRng) -> Result<(Self::SigningKey, Self::VerificationKey)> {
        let (sk, pk) = slh_keygen::<Shake256Hash, N, WOTS_LEN, H_PRIME, D>(rng);
        Ok((SigningKey(sk), VerificationKey(pk)))
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        let sig = slh_sign::<Shake256Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk.0, message, None,
        );
        Ok(Signature(sig))
    }

    fn verify(pk: &Self::VerificationKey, message: &[u8], signature: &Self::Signature) -> Result<()> {
        if slh_verify::<Shake256Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
            &pk.0, message, &signature.0,
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
        let (sk, pk) = SlhDsaShake256f::keygen(&mut rng).unwrap();

        let message = b"Hello, SLH-DSA-SHAKE-256f!";
        let signature = SlhDsaShake256f::sign(&sk, message).unwrap();

        assert!(SlhDsaShake256f::verify(&pk, message, &signature).is_ok());
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(SlhDsaShake256f::SIGNING_KEY_SIZE, 128);
        assert_eq!(SlhDsaShake256f::VERIFICATION_KEY_SIZE, 64);
        assert_eq!(SlhDsaShake256f::SIGNATURE_SIZE, 49856);
    }
}
