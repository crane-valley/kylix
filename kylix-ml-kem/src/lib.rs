//! # ML-KEM (FIPS 203)
//!
//! Implementation of the Module-Lattice-Based Key Encapsulation Mechanism
//! as specified in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
//!
//! ## Parameter Sets
//!
//! | Parameter Set | Security Level | Public Key | Ciphertext | Shared Secret |
//! |---------------|----------------|------------|------------|---------------|
//! | ML-KEM-512    | 1 (128-bit)    | 800 bytes  | 768 bytes  | 32 bytes      |
//! | ML-KEM-768    | 3 (192-bit)    | 1184 bytes | 1088 bytes | 32 bytes      |
//! | ML-KEM-1024   | 5 (256-bit)    | 1568 bytes | 1568 bytes | 32 bytes      |
//!
//! ## Example
//!
//! ```ignore
//! use kylix_ml_kem::{MlKem768, Kem};
//! use rand::rngs::OsRng;
//!
//! let (dk, ek) = MlKem768::keygen(&mut OsRng)?;
//! let (ct, ss_sender) = MlKem768::encaps(&ek, &mut OsRng)?;
//! let ss_receiver = MlKem768::decaps(&dk, &ct)?;
//!
//! assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

mod params;

#[cfg(feature = "ml-kem-512")]
mod ml_kem_512;
#[cfg(feature = "ml-kem-768")]
mod ml_kem_768;
#[cfg(feature = "ml-kem-1024")]
mod ml_kem_1024;

pub use kylix_core::Kem;

#[cfg(feature = "ml-kem-512")]
pub use ml_kem_512::MlKem512;
#[cfg(feature = "ml-kem-768")]
pub use ml_kem_768::MlKem768;
#[cfg(feature = "ml-kem-1024")]
pub use ml_kem_1024::MlKem1024;
