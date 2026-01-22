//! ML-KEM-1024 implementation (NIST Security Level 5).
//!
//! This module provides the ML-KEM-1024 parameter set, which offers
//! 256-bit classical security (NIST Security Level 5).

use crate::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};
use crate::params::ml_kem_1024::*;
use kylix_core::{Error, Kem, Result};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-1024 decapsulation key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    bytes: [u8; DECAPSULATION_KEY_SIZE],
}

impl DecapsulationKey {
    /// Create a decapsulation key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DECAPSULATION_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: DECAPSULATION_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; DECAPSULATION_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Get the key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-1024 encapsulation key.
#[derive(Clone)]
pub struct EncapsulationKey {
    bytes: [u8; ENCAPSULATION_KEY_SIZE],
}

impl EncapsulationKey {
    /// Create an encapsulation key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCAPSULATION_KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: ENCAPSULATION_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut key = [0u8; ENCAPSULATION_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Get the key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-1024 ciphertext.
#[derive(Clone)]
pub struct Ciphertext {
    bytes: [u8; CIPHERTEXT_SIZE],
}

impl Ciphertext {
    /// Create a ciphertext from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextLength {
                expected: CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        let mut ct = [0u8; CIPHERTEXT_SIZE];
        ct.copy_from_slice(bytes);
        Ok(Self { bytes: ct })
    }

    /// Get the ciphertext as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-1024 shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-1024 key encapsulation mechanism.
///
/// Provides NIST Security Level 5 (256-bit classical security).
pub struct MlKem1024;

impl Kem for MlKem1024 {
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

        let (dk_bytes, ek_bytes) = ml_kem_keygen::<K, ETA1>(&d, &z);

        // Zeroize seeds
        d.zeroize();
        z.zeroize();

        Ok((
            DecapsulationKey::from_bytes(&dk_bytes)?,
            EncapsulationKey::from_bytes(&ek_bytes)?,
        ))
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
        assert_eq!(MlKem1024::DECAPSULATION_KEY_SIZE, 3168);
        assert_eq!(MlKem1024::ENCAPSULATION_KEY_SIZE, 1568);
        assert_eq!(MlKem1024::CIPHERTEXT_SIZE, 1568);
        assert_eq!(MlKem1024::SHARED_SECRET_SIZE, 32);
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
    fn test_ml_kem_1024_roundtrip() {
        use rand::thread_rng;

        let (dk, ek) = MlKem1024::keygen(&mut thread_rng()).unwrap();
        let (ct, ss_sender) = MlKem1024::encaps(&ek, &mut thread_rng()).unwrap();
        let ss_receiver = MlKem1024::decaps(&dk, &ct).unwrap();

        assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
    }

    #[test]
    fn test_ml_kem_1024_implicit_rejection() {
        use rand::thread_rng;

        let (dk, ek) = MlKem1024::keygen(&mut thread_rng()).unwrap();
        let (ct, ss_sender) = MlKem1024::encaps(&ek, &mut thread_rng()).unwrap();

        // Corrupt ciphertext
        let mut ct_bytes = ct.as_bytes().to_vec();
        ct_bytes[0] ^= 0xFF;
        let ct_bad = Ciphertext::from_bytes(&ct_bytes).unwrap();

        // Decaps should succeed but return different key
        let ss_bad = MlKem1024::decaps(&dk, &ct_bad).unwrap();
        assert_ne!(ss_sender.as_ref(), ss_bad.as_ref());
    }
}
