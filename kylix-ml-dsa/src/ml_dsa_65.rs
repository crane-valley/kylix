//! ML-DSA-65 (NIST Level 3) implementation

use crate::params::ml_dsa_65::*;
use crate::sign::{expand_verification_key, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, ml_dsa_verify_expanded};
use kylix_core::{Error, Result, Signer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-65 algorithm marker.
pub struct MlDsa65;

/// ML-DSA-65 signing key.
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

/// ML-DSA-65 verification key.
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
    /// Pre-computes expensive values that would otherwise be recomputed
    /// on every `verify()` call:
    /// - Matrix A expansion from SHAKE128
    /// - t1 * 2^D in NTT domain
    /// - H(pk) hash
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (sk, pk) = MlDsa65::keygen(&mut rng)?;
    /// let expanded = pk.expand()?;
    ///
    /// // Fast verification (N times)
    /// for msg in messages {
    ///     let sig = MlDsa65::sign(&sk, msg)?;
    ///     MlDsa65::verify_expanded(&expanded, msg, &sig)?;
    /// }
    /// ```
    pub fn expand(&self) -> Result<ExpandedVerificationKey> {
        expand_verification_key::<K, L>(self.as_bytes())
            .ok_or(Error::EncodingError)
    }
}

/// Expanded verification key with pre-computed values for fast repeated verification.
///
/// See [`VerificationKey::expand`] for usage.
pub type ExpandedVerificationKey = crate::sign::ExpandedVerificationKey<K, L>;

/// ML-DSA-65 signature.
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

impl Signer for MlDsa65 {
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

impl MlDsa65 {
    /// Verify signature using pre-expanded verification key.
    ///
    /// This is faster than [`Signer::verify`] when verifying multiple signatures
    /// with the same public key.
    ///
    /// # Performance
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
    /// let expanded = pk.expand()?;
    /// MlDsa65::verify_expanded(&expanded, message, &signature)?;
    /// ```
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
        assert_eq!(MlDsa65::SIGNING_KEY_SIZE, 4032);
        assert_eq!(MlDsa65::VERIFICATION_KEY_SIZE, 1952);
        assert_eq!(MlDsa65::SIGNATURE_SIZE, 3309);
    }

    #[test]
    fn test_keygen() {
        let mut rng = rand::rng();
        let result = MlDsa65::keygen(&mut rng);
        assert!(result.is_ok());

        let (sk, pk) = result.unwrap();
        assert_eq!(sk.as_bytes().len(), SK_BYTES);
        assert_eq!(pk.as_bytes().len(), PK_BYTES);
    }

    #[test]
    fn test_roundtrip() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

        let message = b"Hello, ML-DSA-65!";
        let signature = MlDsa65::sign(&sk, message).unwrap();

        eprintln!("Signature size: {}", signature.as_bytes().len());
        eprintln!("Expected size: {}", SIG_BYTES);

        let result = MlDsa65::verify(&pk, message, &signature);
        eprintln!("Verification result: {:?}", result);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_expanded_verify() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

        let expanded = pk.expand().expect("expand should succeed");

        let message = b"Test expanded verification";
        let signature = MlDsa65::sign(&sk, message).unwrap();

        // Expanded verify should succeed
        let result = MlDsa65::verify_expanded(&expanded, message, &signature);
        assert!(result.is_ok(), "Expanded verification failed: {:?}", result);

        // Regular verify should also succeed
        let result = MlDsa65::verify(&pk, message, &signature);
        assert!(result.is_ok(), "Regular verification failed: {:?}", result);
    }

    #[test]
    fn test_expanded_verify_wrong_message() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

        let expanded = pk.expand().expect("expand should succeed");

        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let signature = MlDsa65::sign(&sk, message).unwrap();

        // Should fail with wrong message
        let result = MlDsa65::verify_expanded(&expanded, wrong_message, &signature);
        assert!(result.is_err(), "Should fail with wrong message");
    }

    #[test]
    fn test_expanded_verify_multiple_signatures() {
        let mut rng = rand::rng();
        let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();

        let expanded = pk.expand().expect("expand should succeed");

        // Verify multiple signatures with the same expanded key
        for i in 0..5 {
            let message = format!("Message number {}", i);
            let signature = MlDsa65::sign(&sk, message.as_bytes()).unwrap();
            let result = MlDsa65::verify_expanded(&expanded, message.as_bytes(), &signature);
            assert!(result.is_ok(), "Verification {} failed: {:?}", i, result);
        }
    }
}
