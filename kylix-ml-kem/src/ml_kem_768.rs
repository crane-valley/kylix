//! ML-KEM-768 implementation (NIST Security Level 3).

use crate::params::ml_kem_768::*;
use kylix_core::{Error, Kem, Result};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 decapsulation key.
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

/// ML-KEM-768 encapsulation key.
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

/// ML-KEM-768 ciphertext.
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

/// ML-KEM-768 shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-768 key encapsulation mechanism.
///
/// Provides NIST Security Level 3 (192-bit classical security).
pub struct MlKem768;

impl Kem for MlKem768 {
    type DecapsulationKey = DecapsulationKey;
    type EncapsulationKey = EncapsulationKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = SharedSecret;

    const DECAPSULATION_KEY_SIZE: usize = DECAPSULATION_KEY_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = ENCAPSULATION_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize = CIPHERTEXT_SIZE;
    const SHARED_SECRET_SIZE: usize = SHARED_SECRET_SIZE;

    fn keygen(
        _rng: &mut impl CryptoRng,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey)> {
        // TODO: Implement ML-KEM-768.KeyGen() as per FIPS 203 Algorithm 16
        unimplemented!("ML-KEM-768 key generation not yet implemented")
    }

    fn encaps(
        _ek: &Self::EncapsulationKey,
        _rng: &mut impl CryptoRng,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        // TODO: Implement ML-KEM-768.Encaps() as per FIPS 203 Algorithm 17
        unimplemented!("ML-KEM-768 encapsulation not yet implemented")
    }

    fn decaps(_dk: &Self::DecapsulationKey, _ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        // TODO: Implement ML-KEM-768.Decaps() as per FIPS 203 Algorithm 18
        unimplemented!("ML-KEM-768 decapsulation not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        assert_eq!(MlKem768::DECAPSULATION_KEY_SIZE, 2400);
        assert_eq!(MlKem768::ENCAPSULATION_KEY_SIZE, 1184);
        assert_eq!(MlKem768::CIPHERTEXT_SIZE, 1088);
        assert_eq!(MlKem768::SHARED_SECRET_SIZE, 32);
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
}
