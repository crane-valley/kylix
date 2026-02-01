//! # Kylix Core
//!
//! Core traits and utilities for the Kylix post-quantum cryptography library.
//!
//! This crate provides:
//! - Common error types
//! - Cryptographic primitive traits (`Kem`, `Signer`)
//! - Modular arithmetic macros for lattice-based cryptography
//! - NTT (Number Theoretic Transform) macros for polynomial multiplication
//! - Secure memory handling with zeroize integration

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

mod error;
mod ntt;
mod reduce;
mod traits;

pub use error::{Error, Result};
pub use traits::{Kem, Signer};

/// Re-export zeroize for convenience.
pub use zeroize::{Zeroize, ZeroizeOnDrop};

/// Re-export subtle for constant-time operations.
pub use subtle;
