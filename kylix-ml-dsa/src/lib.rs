//! ML-DSA (FIPS 204) Implementation
//!
//! This crate provides a pure Rust implementation of the ML-DSA digital signature
//! algorithm as specified in FIPS 204.
//!
//! # Supported Parameter Sets
//!
//! | Variant | Security Level | Public Key | Signature |
//! |---------|----------------|------------|-----------|
//! | ML-DSA-44 | Level 2 | 1,312 bytes | 2,420 bytes |
//! | ML-DSA-65 | Level 3 | 1,952 bytes | 3,309 bytes |
//! | ML-DSA-87 | Level 5 | 2,592 bytes | 4,627 bytes |
//!
//! # Example
//!
//! ```ignore
//! use kylix_ml_dsa::MlDsa65;
//! use kylix_core::Signer;
//!
//! let mut rng = rand::rng();
//! let (sk, pk) = MlDsa65::keygen(&mut rng).unwrap();
//!
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa65::sign(&sk, message).unwrap();
//!
//! assert!(MlDsa65::verify(&pk, message, &signature).is_ok());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::module_name_repetitions
)]

#[allow(dead_code)]
mod reduce;
#[allow(dead_code)]
mod poly;
#[allow(dead_code)]
mod ntt;
#[allow(dead_code)]
mod hash;
#[allow(dead_code)]
mod sample;
#[allow(dead_code)]
mod rounding;
#[allow(dead_code)]
mod packing;
#[allow(dead_code)]
mod polyvec;
#[allow(dead_code)]
mod sign;
#[allow(dead_code)]
mod params;

#[cfg(feature = "ml-dsa-44")]
mod ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
mod ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
mod ml_dsa_87;

#[cfg(feature = "ml-dsa-44")]
pub use ml_dsa_44::MlDsa44;
#[cfg(feature = "ml-dsa-65")]
pub use ml_dsa_65::MlDsa65;
#[cfg(feature = "ml-dsa-87")]
pub use ml_dsa_87::MlDsa87;

// Re-export variant modules for access to specific types
/// ML-DSA-44 (NIST Security Level 2) - 128-bit classical security.
#[cfg(feature = "ml-dsa-44")]
pub mod dsa44 {
    pub use crate::ml_dsa_44::*;
}

/// ML-DSA-65 (NIST Security Level 3) - 192-bit classical security.
#[cfg(feature = "ml-dsa-65")]
pub mod dsa65 {
    pub use crate::ml_dsa_65::*;
}

/// ML-DSA-87 (NIST Security Level 5) - 256-bit classical security.
#[cfg(feature = "ml-dsa-87")]
pub mod dsa87 {
    pub use crate::ml_dsa_87::*;
}

pub use kylix_core::{Error, Result, Signer};
