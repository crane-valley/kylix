//! ML-KEM-512 implementation (NIST Security Level 1).

use crate::params::ml_kem_512::*;
use kylix_core::{Error, Kem, Result};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-512 decapsulation key.
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

/// ML-KEM-512 encapsulation key.
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

/// ML-KEM-512 ciphertext.
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

/// ML-KEM-512 shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
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
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey)> {
        // TODO: Implement ML-KEM-512.KeyGen() as per FIPS 203 Algorithm 16
        unimplemented!("ML-KEM-512 key generation not yet implemented")
    }

    fn encaps(
        _ek: &Self::EncapsulationKey,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        // TODO: Implement ML-KEM-512.Encaps() as per FIPS 203 Algorithm 17
        unimplemented!("ML-KEM-512 encapsulation not yet implemented")
    }

    fn decaps(_dk: &Self::DecapsulationKey, _ct: &Self::Ciphertext) -> Result<Self::SharedSecret> {
        // TODO: Implement ML-KEM-512.Decaps() as per FIPS 203 Algorithm 18
        unimplemented!("ML-KEM-512 decapsulation not yet implemented")
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
}
