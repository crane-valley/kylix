//! ML-KEM-512 implementation (NIST Security Level 1).
//!
//! This module provides the ML-KEM-512 parameter set, which offers
//! 128-bit classical security (NIST Security Level 1).

use crate::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};
use crate::params::ml_kem_512::*;
use crate::types::define_kem_types;
use kylix_core::{Error, Kem, Result};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

define_kem_types! {
    dk_size: DECAPSULATION_KEY_SIZE,
    ek_size: ENCAPSULATION_KEY_SIZE,
    ct_size: CIPHERTEXT_SIZE,
    ss_size: SHARED_SECRET_SIZE
}

/// ML-KEM-512 key encapsulation mechanism.
///
/// Provides NIST Security Level 1 (128-bit classical security).
pub struct MlKem512;

impl Kem for MlKem512 {
    type DecapsulationKey = DecapsulationKey;
    type EncapsulationKey = EncapsulationKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = SharedSecret;

    const DECAPSULATION_KEY_SIZE: usize = DECAPSULATION_KEY_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = ENCAPSULATION_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize = CIPHERTEXT_SIZE;
    const SHARED_SECRET_SIZE: usize = SHARED_SECRET_SIZE;

    fn keygen(
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey)> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut d);
        rng.fill_bytes(&mut z);

        let (mut dk_bytes, ek_bytes) = ml_kem_keygen::<K, ETA1>(&d, &z);

        // Zeroize seeds
        d.zeroize();
        z.zeroize();

        let dk_res = DecapsulationKey::from_bytes(&dk_bytes);
        dk_bytes.zeroize();
        let dk = dk_res?;

        let ek = EncapsulationKey::from_bytes(&ek_bytes)?;

        Ok((dk, ek))
    }

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);

        let (ct_bytes, ss_bytes) = ml_kem_encaps::<K, ETA1, ETA2, DU, DV>(ek.as_bytes(), &m);

        // Zeroize message
        m.zeroize();

        Ok((
            Ciphertext::from_bytes(&ct_bytes)?,
            SharedSecret { bytes: ss_bytes },
        ))
    }

    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        let ss_bytes = ml_kem_decaps::<K, ETA1, ETA2, DU, DV>(dk.as_bytes(), ct.as_bytes());
        Ok(SharedSecret { bytes: ss_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(MlKem512::DECAPSULATION_KEY_SIZE, 1632);
        assert_eq!(MlKem512::ENCAPSULATION_KEY_SIZE, 800);
        assert_eq!(MlKem512::CIPHERTEXT_SIZE, 768);
        assert_eq!(MlKem512::SHARED_SECRET_SIZE, 32);
    }

    #[test]
    fn test_encapsulation_key_from_bytes() {
        let bytes = [0u8; ENCAPSULATION_KEY_SIZE];
        let ek = EncapsulationKey::from_bytes(&bytes).unwrap();
        assert_eq!(ek.as_bytes(), &bytes);
    }

    #[test]
    fn test_encapsulation_key_invalid_length() {
        let bytes = [0u8; 100];
        let result = EncapsulationKey::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        use rand::rng;

        let (dk, ek) = MlKem512::keygen(&mut rng()).unwrap();
        let (ct, ss_sender) = MlKem512::encaps(&ek, &mut rng()).unwrap();
        let ss_receiver = MlKem512::decaps(&dk, &ct).unwrap();

        assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
    }

    #[test]
    fn test_ml_kem_512_implicit_rejection() {
        use rand::rng;

        let (dk, ek) = MlKem512::keygen(&mut rng()).unwrap();
        let (ct, ss_sender) = MlKem512::encaps(&ek, &mut rng()).unwrap();

        // Corrupt ciphertext
        let mut ct_bytes = ct.as_bytes().to_vec();
        ct_bytes[0] ^= 0xFF;
        let ct_bad = Ciphertext::from_bytes(&ct_bytes).unwrap();

        // Decaps should succeed but return different key
        let ss_bad = MlKem512::decaps(&dk, &ct_bad).unwrap();
        assert_ne!(ss_sender.as_ref(), ss_bad.as_ref());
    }
}
