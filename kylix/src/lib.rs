//! # Kylix
//!
//! A post-quantum cryptography library implementing NIST FIPS standards.
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `ml-kem` (default): Enable ML-KEM (FIPS 203) key encapsulation
//! - `ml-dsa` (default): Enable ML-DSA (FIPS 204) digital signatures
//!
//! ## Supported Algorithms
//!
//! - **ML-KEM** (FIPS 203): Module-Lattice-Based Key Encapsulation Mechanism
//!   - ML-KEM-512
//!   - ML-KEM-768
//!   - ML-KEM-1024
//! - **ML-DSA** (FIPS 204): Module-Lattice-Based Digital Signature Algorithm
//!   - ML-DSA-44
//!   - ML-DSA-65
//!   - ML-DSA-87
//!
//! ## Example
//!
//! ```ignore
//! use kylix::ml_kem::{MlKem768, Kem};
//!
//! // Generate a key pair
//! let (dk, ek) = MlKem768::keygen(&mut rng)?;
//!
//! // Encapsulate a shared secret
//! let (ct, ss_sender) = MlKem768::encaps(&ek, &mut rng)?;
//!
//! // Decapsulate the shared secret
//! let ss_receiver = MlKem768::decaps(&dk, &ct)?;
//!
//! assert_eq!(ss_sender, ss_receiver);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub use kylix_core::{Error, Result};

/// Core traits for cryptographic primitives.
pub mod traits {
    pub use kylix_core::{Kem, Signer};
}

/// ML-KEM (FIPS 203) key encapsulation mechanism.
#[cfg(feature = "ml-kem")]
pub mod ml_kem {
    pub use kylix_core::Kem;
    pub use kylix_ml_kem::*;
}

/// ML-DSA (FIPS 204) digital signature algorithm.
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa {
    pub use kylix_core::Signer;
    pub use kylix_ml_dsa::*;
}

/// SLH-DSA (FIPS 205) stateless hash-based digital signature algorithm.
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa {
    pub use kylix_core::Signer;
    pub use kylix_slh_dsa::*;
}
