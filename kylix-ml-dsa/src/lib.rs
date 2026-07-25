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
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
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

mod hash;
mod ntt;
mod packing;
/// ML-DSA parameter constants for all variants.
pub mod params;
mod poly;
mod polyvec;
mod reduce;
mod rounding;
mod sample;
/// Low-level ML-DSA signing algorithms, kept public only for ACVP vectors and
/// timing harnesses that need deterministic entry points.
///
/// Use `MlDsa44`, `MlDsa65`, or `MlDsa87` instead. This module is hidden from
/// rustdoc to discourage use; it is still part of the public API surface, so
/// changes to it remain semver-breaking.
#[doc(hidden)]
pub mod sign;
#[cfg(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]
mod types;

// SIMD optimizations (optional, platform-specific)
#[cfg(feature = "simd")]
pub(crate) mod simd;

#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44;
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65;
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87;

#[cfg(feature = "ml-dsa-44")]
pub use ml_dsa_44::MlDsa44;
#[cfg(feature = "ml-dsa-65")]
pub use ml_dsa_65::MlDsa65;
#[cfg(feature = "ml-dsa-87")]
pub use ml_dsa_87::MlDsa87;

// Legacy aliases for the variant modules, kept so existing `dsa*` paths keep
// resolving. They re-export everything the `ml_dsa_*` modules expose.
//
// The `#[deprecated]` attribute only fires when the module is named as an item
// (`use kylix_ml_dsa::dsa65;`). rustc does not report it for a path that merely
// passes through the module (`use kylix_ml_dsa::dsa65::SigningKey;`), so most
// downstream code gets no warning. The attribute is kept anyway for the cases
// it does cover; do not assume it flags every legacy use site.
/// Deprecated alias for [`ml_dsa_44`].
#[cfg(feature = "ml-dsa-44")]
#[deprecated(since = "0.5.0", note = "renamed to `ml_dsa_44`")]
pub mod dsa44 {
    pub use crate::ml_dsa_44::*;
}

/// Deprecated alias for [`ml_dsa_65`].
///
/// ```no_run
/// #[allow(deprecated)]
/// use kylix_ml_dsa::dsa65; // prefer `kylix_ml_dsa::ml_dsa_65`
/// let _: Option<dsa65::SigningKey> = None;
/// ```
#[cfg(feature = "ml-dsa-65")]
#[deprecated(since = "0.5.0", note = "renamed to `ml_dsa_65`")]
pub mod dsa65 {
    pub use crate::ml_dsa_65::*;
}

/// Deprecated alias for [`ml_dsa_87`].
#[cfg(feature = "ml-dsa-87")]
#[deprecated(since = "0.5.0", note = "renamed to `ml_dsa_87`")]
pub mod dsa87 {
    pub use crate::ml_dsa_87::*;
}

pub use kylix_core::{Error, Result, Signer};
