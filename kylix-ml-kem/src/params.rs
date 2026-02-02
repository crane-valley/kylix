//! ML-KEM parameter sets as defined in FIPS 203.

/// Common parameters for all ML-KEM variants.
#[allow(dead_code)]
pub mod common {
    /// Polynomial ring dimension (n).
    pub const N: usize = 256;

    /// Modulus (q).
    pub const Q: u16 = 3329;

    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = 32;

    /// Seed size for key generation.
    pub const SEED_SIZE: usize = 32;
}

/// ML-KEM-512 parameters (NIST Security Level 1).
#[cfg(feature = "ml-kem-512")]
pub mod ml_kem_512 {

    /// Module rank (k).
    pub const K: usize = 2;

    /// Compression parameter for public key (du).
    pub const DU: usize = 10;

    /// Compression parameter for ciphertext (dv).
    pub const DV: usize = 4;

    /// Noise parameter (eta1).
    pub const ETA1: usize = 3;

    /// Noise parameter (eta2).
    pub const ETA2: usize = 2;

    /// Encapsulation key size in bytes.
    pub const ENCAPSULATION_KEY_SIZE: usize = 800;

    /// Decapsulation key size in bytes.
    pub const DECAPSULATION_KEY_SIZE: usize = 1632;

    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 768;

    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = super::common::SHARED_SECRET_SIZE;
}

/// ML-KEM-768 parameters (NIST Security Level 3).
#[cfg(feature = "ml-kem-768")]
pub mod ml_kem_768 {

    /// Module rank (k).
    pub const K: usize = 3;

    /// Compression parameter for public key (du).
    pub const DU: usize = 10;

    /// Compression parameter for ciphertext (dv).
    pub const DV: usize = 4;

    /// Noise parameter (eta1).
    pub const ETA1: usize = 2;

    /// Noise parameter (eta2).
    pub const ETA2: usize = 2;

    /// Encapsulation key size in bytes.
    pub const ENCAPSULATION_KEY_SIZE: usize = 1184;

    /// Decapsulation key size in bytes.
    pub const DECAPSULATION_KEY_SIZE: usize = 2400;

    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1088;

    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = super::common::SHARED_SECRET_SIZE;
}

/// ML-KEM-1024 parameters (NIST Security Level 5).
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem_1024 {

    /// Module rank (k).
    pub const K: usize = 4;

    /// Compression parameter for public key (du).
    pub const DU: usize = 11;

    /// Compression parameter for ciphertext (dv).
    pub const DV: usize = 5;

    /// Noise parameter (eta1).
    pub const ETA1: usize = 2;

    /// Noise parameter (eta2).
    pub const ETA2: usize = 2;

    /// Encapsulation key size in bytes.
    pub const ENCAPSULATION_KEY_SIZE: usize = 1568;

    /// Decapsulation key size in bytes.
    pub const DECAPSULATION_KEY_SIZE: usize = 3168;

    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 1568;

    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = super::common::SHARED_SECRET_SIZE;
}
