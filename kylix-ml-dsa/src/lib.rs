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
//! ```no_run
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
// Clippy allowances for cryptographic code patterns:
// - many_single_char_names: Mathematical notation (a, b, c, t, r, z, etc.)
// - similar_names: Intentional for related variables (s1/s2, t0/t1)
// - too_many_arguments: Generic const parameters for security levels
// - cast_possible_truncation/sign_loss/wrap: Intentional for modular arithmetic
//   All casts are verified to be within bounds for q=8380417 (23-bit)
// - cast_lossless: Explicit u8->i32 casts in bit-packing are clearer than From
// - module_name_repetitions: MlDsa65 in ml_dsa_65 module is acceptable
// - unreadable_literal: NTT zeta constants are from FIPS 204 spec, keeping original format
// - must_use_candidate: Not all getters need #[must_use] in crypto code
// - missing_errors_doc: Error documentation is in the Error type itself
// - missing_panics_doc: Panics are documented where non-obvious
// - doc_markdown: Math notation doesn't need backticks (R_q, Z_q, etc.)
// - wildcard_imports: Parameter imports (K, L, ETA, etc.) are cleaner as wildcards
// - too_many_lines: Crypto functions (sign/verify) are inherently long algorithms
// - items_after_statements: Constants near their usage aids readability
// - needless_borrow: Explicit borrows for slice arguments improve clarity
// - needless_range_loop: Index-based loops are clearer for crypto indexing patterns
// - assign_op_pattern: Explicit a[j] = a[j] + t matches FIPS 204 specification
// - precedence: Bit manipulation patterns are standard in crypto (e.g., 205*t >> 10)
// - large_types_passed_by_value: Poly::new takes array by value for const fn compatibility
// - manual_range_contains: Explicit comparisons are clearer in assertions
// - redundant_closure_for_method_calls: Closure |p| p.norm_inf() is clearer than Poly::norm_inf
// - uninlined_format_args: Format args are clearer with explicit variable names
// - unnecessary_cast: ETA as usize is consistent with other const generic usage
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::needless_borrow,
    clippy::needless_range_loop,
    clippy::assign_op_pattern,
    clippy::precedence,
    clippy::large_types_passed_by_value,
    clippy::manual_range_contains,
    clippy::redundant_closure_for_method_calls,
    clippy::uninlined_format_args,
    clippy::unnecessary_cast
)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[allow(dead_code)]
mod hash;
#[allow(dead_code)]
mod ntt;
#[allow(dead_code)]
mod packing;
/// ML-DSA parameter constants for all variants.
pub mod params;
#[allow(dead_code)]
mod poly;
#[allow(dead_code)]
mod polyvec;
#[allow(dead_code)]
mod reduce;
#[allow(dead_code)]
mod rounding;
#[allow(dead_code)]
mod sample;
/// Core signing algorithms (internal API for ACVP testing).
#[allow(dead_code)]
pub mod sign;

// SIMD optimizations (optional, platform-specific)
#[cfg(feature = "simd")]
pub(crate) mod simd;

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
