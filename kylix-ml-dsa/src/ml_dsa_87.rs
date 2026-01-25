//! ML-DSA-87 (NIST Level 5) implementation

use crate::params::ml_dsa_87::*;
use crate::sign::{
    expand_verification_key, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, ml_dsa_verify_expanded,
};
use kylix_core::{Error, Result, Signer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-87 algorithm marker.
pub struct MlDsa87;

/// ML-DSA-87 signing key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    bytes: [u8; SK_BYTES],
}

impl SigningKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: SK_BYTES,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; SK_BYTES];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SK_BYTES] {
        &self.bytes
    }
}

/// ML-DSA-87 verification key.
#[derive(Clone)]
pub struct VerificationKey {
    bytes: [u8; PK_BYTES],
}

impl VerificationKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: PK_BYTES,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; PK_BYTES];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; PK_BYTES] {
        &self.bytes
    }

    /// Expand the verification key for fast repeated verification.
    ///
    /// See [`crate::ml_dsa_65::VerificationKey::expand`] for details.
    pub fn expand(&self) -> Result<ExpandedVerificationKey> {
        expand_verification_key::<K, L>(self.as_bytes()).ok_or(Error::EncodingError)
    }
}

/// Expanded verification key with pre-computed values for fast repeated verification.
pub type ExpandedVerificationKey = crate::sign::ExpandedVerificationKey<K, L>;

/// ML-DSA-87 signature.
#[derive(Clone)]
pub struct Signature {
    bytes: [u8; SIG_BYTES],
}

impl Signature {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIG_BYTES {
            return Err(Error::InvalidSignatureLength {
                expected: SIG_BYTES,
                actual: bytes.len(),
            });
        }
        let mut sig = [0u8; SIG_BYTES];
        sig.copy_from_slice(bytes);
        Ok(Self { bytes: sig })
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SIG_BYTES] {
        &self.bytes
    }
}

impl Signer for MlDsa87 {
    type SigningKey = SigningKey;
    type VerificationKey = VerificationKey;
    type Signature = Signature;

    const SIGNING_KEY_SIZE: usize = SK_BYTES;
    const VERIFICATION_KEY_SIZE: usize = PK_BYTES;
    const SIGNATURE_SIZE: usize = SIG_BYTES;

    fn keygen(rng: &mut impl CryptoRng) -> Result<(Self::SigningKey, Self::VerificationKey)> {
        let mut xi = [0u8; 32];
        rng.fill_bytes(&mut xi);

        let (sk_bytes, pk_bytes) = ml_dsa_keygen::<K, L, ETA>(&xi);

        xi.zeroize();

        let sk = SigningKey::from_bytes(&sk_bytes)?;
        let pk = VerificationKey::from_bytes(&pk_bytes)?;

        Ok((sk, pk))
    }

    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Result<Self::Signature> {
        // Use deterministic signing (rnd = 0)
        let rnd = [0u8; 32];

        let sig_bytes = ml_dsa_sign::<K, L, ETA, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
            sk.as_bytes(),
            message,
            &rnd,
        )
        .ok_or(Error::EncodingError)?;

        Signature::from_bytes(&sig_bytes)
    }

    fn verify(
        pk: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()> {
        let valid = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
            pk.as_bytes(),
            message,
            signature.as_bytes(),
        );

        if valid {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

impl MlDsa87 {
    /// Verify signature using pre-expanded verification key.
    ///
    /// See [`crate::ml_dsa_65::MlDsa65::verify_expanded`] for details.
    pub fn verify_expanded(
        expanded: &ExpandedVerificationKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        let valid = ml_dsa_verify_expanded::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
            expanded,
            message,
            signature.as_bytes(),
        );

        if valid {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(MlDsa87::SIGNING_KEY_SIZE, 4896);
        assert_eq!(MlDsa87::VERIFICATION_KEY_SIZE, 2592);
        assert_eq!(MlDsa87::SIGNATURE_SIZE, 4627);
    }

    #[test]
    fn test_keygen() {
        let mut rng = rand::rng();
        let result = MlDsa87::keygen(&mut rng);
        assert!(result.is_ok());

        let (sk, pk) = result.unwrap();
        assert_eq!(sk.as_bytes().len(), SK_BYTES);
        assert_eq!(pk.as_bytes().len(), PK_BYTES);
    }

    #[test]
    fn test_roundtrip() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa87::keygen(&mut rng).unwrap();

        let message = b"Hello, ML-DSA-87!";
        let signature = MlDsa87::sign(&sk, message).unwrap();

        let result = MlDsa87::verify(&pk, message, &signature);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_expanded_verify() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa87::keygen(&mut rng).unwrap();

        let expanded = pk.expand().expect("expand should succeed");

        let message = b"Test expanded verification";
        let signature = MlDsa87::sign(&sk, message).unwrap();

        let result = MlDsa87::verify_expanded(&expanded, message, &signature);
        assert!(result.is_ok(), "Expanded verification failed: {:?}", result);
    }
}
