//! # Kylix
//!
//! A post-quantum cryptography library implementing NIST FIPS standards.
//!
//! ## Features
//!
//! - `std` (default): Enable standard library support
//! - `ml-kem` (default): Enable ML-KEM (FIPS 203) key encapsulation
//!
//! ## Supported Algorithms
//!
//! - **ML-KEM** (FIPS 203): Module-Lattice-Based Key Encapsulation Mechanism
//!   - ML-KEM-512
//!   - ML-KEM-768
//!   - ML-KEM-1024
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
