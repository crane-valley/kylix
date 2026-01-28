//! ML-DSA-87 (NIST Level 5) implementation

use crate::params::ml_dsa_87::*;
use crate::sign::{
    expand_verification_key, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, ml_dsa_verify_expanded,
};
use crate::types::define_dsa_types;
use kylix_core::{Error, Result, Signer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-87 algorithm marker.
pub struct MlDsa87;

define_dsa_types! {
    sk_size: SK_BYTES,
    pk_size: PK_BYTES,
    sig_size: SIG_BYTES,
    K: K,
    L: L
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

        let (mut sk_bytes, pk_bytes) = ml_dsa_keygen::<K, L, ETA>(&xi);

        xi.zeroize();

        let sk = SigningKey::from_bytes(&sk_bytes)?;
        sk_bytes.zeroize();

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
