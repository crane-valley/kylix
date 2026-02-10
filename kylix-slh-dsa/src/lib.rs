//! SLH-DSA (FIPS 205) Implementation
//!
//! This crate provides a pure Rust implementation of the SLH-DSA digital signature
//! algorithm as specified in FIPS 205. SLH-DSA is a stateless hash-based signature
//! scheme, providing post-quantum security based solely on the security of hash functions.
//!
//! # Supported Parameter Sets
//!
//! ## SHAKE-based variants (recommended)
//!
//! | Variant | Security Level | Public Key | Signature |
//! |---------|----------------|------------|-----------|
//! | SLH-DSA-SHAKE-128s | Level 1 | 32 bytes | 7,856 bytes |
//! | SLH-DSA-SHAKE-128f | Level 1 | 32 bytes | 17,088 bytes |
//! | SLH-DSA-SHAKE-192s | Level 3 | 48 bytes | 16,224 bytes |
//! | SLH-DSA-SHAKE-192f | Level 3 | 48 bytes | 35,664 bytes |
//! | SLH-DSA-SHAKE-256s | Level 5 | 64 bytes | 29,792 bytes |
//! | SLH-DSA-SHAKE-256f | Level 5 | 64 bytes | 49,856 bytes |
//!
//! ## SHA2-based variants
//!
//! | Variant | Security Level | Public Key | Signature |
//! |---------|----------------|------------|-----------|
//! | SLH-DSA-SHA2-128s | Level 1 | 32 bytes | 7,856 bytes |
//! | SLH-DSA-SHA2-128f | Level 1 | 32 bytes | 17,088 bytes |
//! | SLH-DSA-SHA2-192s | Level 3 | 48 bytes | 16,224 bytes |
//! | SLH-DSA-SHA2-192f | Level 3 | 48 bytes | 35,664 bytes |
//! | SLH-DSA-SHA2-256s | Level 5 | 64 bytes | 29,792 bytes |
//! | SLH-DSA-SHA2-256f | Level 5 | 64 bytes | 49,856 bytes |
//!
//! The "s" variants produce smaller signatures but are slower to sign.
//! The "f" variants are faster to sign but produce larger signatures.
//!
//! # Architecture
//!
//! SLH-DSA combines three main components:
//! - **WOTS+**: Winternitz One-Time Signature scheme for efficient one-time signing
//! - **FORS**: Forest of Random Subsets for few-time message signing
//! - **Hypertree**: Multi-layer XMSS tree structure for key management
//!
//! # Example
//!
//! ```rust
//! use kylix_slh_dsa::SlhDsaShake128f;
//! use kylix_core::Signer;
//!
//! let mut rng = rand::rng();
//! let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();
//!
//! let message = b"Hello, post-quantum world!";
//! let signature = SlhDsaShake128f::sign(&sk, message).unwrap();
//!
//! assert!(SlhDsaShake128f::verify(&pk, message, &signature).is_ok());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]
// Clippy allowances for cryptographic code patterns
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::needless_range_loop
)]

// alloc is available in both std and no_std environments
extern crate alloc;

// Core modules
mod address;
mod hash;
/// SHA2-based hash function implementations.
#[cfg(feature = "any-sha2-variant")]
pub mod hash_sha2;
/// SHAKE-based hash function implementations.
pub mod hash_shake;
/// SLH-DSA parameter constants for all variants.
pub mod params;
#[cfg(feature = "any-variant")]
mod types;
mod utils;

// Building blocks
mod fors;
mod hypertree;
mod wots;
mod xmss;

// Parallel implementations (requires rayon)
#[cfg(feature = "parallel")]
mod parallel;

// Main signing module
/// Core SLH-DSA signing algorithms.
pub mod sign;

// Variant-specific modules (public for access to SigningKey, VerificationKey, Signature types)
#[cfg(feature = "slh-dsa-shake-128f")]
pub mod slh_dsa_shake_128f;
#[cfg(feature = "slh-dsa-shake-128s")]
pub mod slh_dsa_shake_128s;
#[cfg(feature = "slh-dsa-shake-192f")]
pub mod slh_dsa_shake_192f;
#[cfg(feature = "slh-dsa-shake-192s")]
pub mod slh_dsa_shake_192s;
#[cfg(feature = "slh-dsa-shake-256f")]
pub mod slh_dsa_shake_256f;
#[cfg(feature = "slh-dsa-shake-256s")]
pub mod slh_dsa_shake_256s;

// SHA2 variant modules
#[cfg(feature = "slh-dsa-sha2-128f")]
pub mod slh_dsa_sha2_128f;
#[cfg(feature = "slh-dsa-sha2-128s")]
pub mod slh_dsa_sha2_128s;
#[cfg(feature = "slh-dsa-sha2-192f")]
pub mod slh_dsa_sha2_192f;
#[cfg(feature = "slh-dsa-sha2-192s")]
pub mod slh_dsa_sha2_192s;
#[cfg(feature = "slh-dsa-sha2-256f")]
pub mod slh_dsa_sha2_256f;
#[cfg(feature = "slh-dsa-sha2-256s")]
pub mod slh_dsa_sha2_256s;

// Public exports
pub use address::{Address, AdrsType};
pub use hash::HashSuite;
#[cfg(feature = "any-sha2-variant")]
pub use hash_sha2::{Sha2_128Hash, Sha2_192Hash, Sha2_256Hash};
pub use hash_shake::{Shake128Hash, Shake192Hash, Shake256Hash};

// Re-export core types
pub use kylix_core::{Error, Result, Signer};

// Variant exports
#[cfg(feature = "slh-dsa-shake-128f")]
pub use slh_dsa_shake_128f::SlhDsaShake128f;
#[cfg(feature = "slh-dsa-shake-128s")]
pub use slh_dsa_shake_128s::SlhDsaShake128s;
#[cfg(feature = "slh-dsa-shake-192f")]
pub use slh_dsa_shake_192f::SlhDsaShake192f;
#[cfg(feature = "slh-dsa-shake-192s")]
pub use slh_dsa_shake_192s::SlhDsaShake192s;
#[cfg(feature = "slh-dsa-shake-256f")]
pub use slh_dsa_shake_256f::SlhDsaShake256f;
#[cfg(feature = "slh-dsa-shake-256s")]
pub use slh_dsa_shake_256s::SlhDsaShake256s;

// SHA2 variant exports
#[cfg(feature = "slh-dsa-sha2-128f")]
pub use slh_dsa_sha2_128f::SlhDsaSha2_128f;
#[cfg(feature = "slh-dsa-sha2-128s")]
pub use slh_dsa_sha2_128s::SlhDsaSha2_128s;
#[cfg(feature = "slh-dsa-sha2-192f")]
pub use slh_dsa_sha2_192f::SlhDsaSha2_192f;
#[cfg(feature = "slh-dsa-sha2-192s")]
pub use slh_dsa_sha2_192s::SlhDsaSha2_192s;
#[cfg(feature = "slh-dsa-sha2-256f")]
pub use slh_dsa_sha2_256f::SlhDsaSha2_256f;
#[cfg(feature = "slh-dsa-sha2-256s")]
pub use slh_dsa_sha2_256s::SlhDsaSha2_256s;
