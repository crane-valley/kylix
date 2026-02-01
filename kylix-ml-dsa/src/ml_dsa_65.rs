//! ML-DSA-65 (NIST Level 3) implementation

use crate::params::ml_dsa_65::*;
use crate::sign::{
    expand_verification_key, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, ml_dsa_verify_expanded,
};
use crate::types::define_dsa_types;
use kylix_core::{Error, Result, Signer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ML-DSA-65 algorithm marker.
pub struct MlDsa65;

define_dsa_types! {
    sk_size: SK_BYTES,
    pk_size: PK_BYTES,
    sig_size: SIG_BYTES,
    K: K,
    L: L
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
        let sk_bytes = Zeroizing::new(sk_bytes);

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
    /// // Expand the verification key once
    /// let expanded = pk.expand()?;
    ///
    /// // Verify multiple (message, signature) pairs efficiently
    /// for (message, signature) in messages_and_signatures {
    ///     MlDsa65::verify_expanded(&expanded, message, &signature)?;
    /// }
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
