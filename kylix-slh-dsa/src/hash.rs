//! Hash function abstraction for SLH-DSA.
//!
//! SLH-DSA uses several specialized hash functions for different purposes.
//! This module defines the `HashSuite` trait that abstracts over SHAKE and SHA2 variants.
//!
//! FIPS 205 defines the following hash functions:
//! - **PRF**: Pseudorandom function for secret key generation
//! - **PRFmsg**: Pseudorandom function for message randomization
//! - **Hmsg**: Hash function for message digest generation
//! - **F**: Chaining function for WOTS+
//! - **H**: Two-to-one hash function for Merkle trees
//! - **Tl**: Multi-input hash function for WOTS+ and FORS public key compression

use crate::address::Address;
use zeroize::Zeroizing;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Hash function suite trait for SLH-DSA.
///
/// Implementations of this trait provide the complete set of hash functions
/// required for a specific SLH-DSA variant (SHAKE or SHA2 based).
pub trait HashSuite {
    /// Security parameter n (hash output length in bytes).
    /// - 16 for 128-bit security
    /// - 24 for 192-bit security
    /// - 32 for 256-bit security
    const N: usize;

    /// PRF: Generate n-byte pseudorandom output for secret key material.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: WOTS+ and FORS secret key generation
    ///
    /// # Arguments
    /// * `pk_seed` - Public seed (n bytes)
    /// * `sk_seed` - Secret seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    ///
    /// # Returns
    /// n-byte pseudorandom output wrapped in `Zeroizing` for automatic memory cleanup
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>>;

    /// PRFmsg: Generate n-byte randomizer for message signing.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: Generating the randomizer R in signature generation
    ///
    /// # Arguments
    /// * `sk_prf` - Secret PRF key (n bytes)
    /// * `opt_rand` - Optional randomness (n bytes, can be PK.seed for deterministic signing)
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// n-byte randomizer wrapped in `Zeroizing` for automatic memory cleanup
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>>;

    /// Hmsg: Generate message digest for FORS signing.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: Generating the digest that determines FORS indices
    ///
    /// # Arguments
    /// * `r` - Randomizer (n bytes)
    /// * `pk_seed` - Public seed (n bytes)
    /// * `pk_root` - Public root (n bytes)
    /// * `message` - Message to sign
    /// * `out_len` - Required output length in bytes
    ///
    /// # Returns
    /// Message digest of specified length
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8], out_len: usize) -> Vec<u8>;

    /// F: Chaining function for WOTS+.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: WOTS+ chain computation
    ///
    /// # Arguments
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m1` - Input message (n bytes)
    ///
    /// # Returns
    /// n-byte hash output
    fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8>;

    /// H: Two-to-one hash function.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: Merkle tree node computation
    ///
    /// # Arguments
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m1` - Left child (n bytes)
    /// * `m2` - Right child (n bytes)
    ///
    /// # Returns
    /// n-byte hash output
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8>;

    /// Tl: Multi-input hash function.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2)
    ///
    /// Used for: WOTS+ and FORS public key compression
    ///
    /// # Arguments
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m` - Input message (l*n bytes where l is the number of inputs)
    ///
    /// # Returns
    /// n-byte hash output
    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8>;

    // --- Buffer-write variants ---
    // These write directly into a caller-provided buffer instead of allocating.
    // Default implementations delegate to the Vec-returning methods.

    /// F into a caller-provided buffer (n bytes).
    ///
    /// # Panics
    /// Panics in debug builds if `out.len() != N`.
    fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
        let result = Self::f(pk_seed, adrs, m1);
        out.copy_from_slice(&result);
    }

    /// H into a caller-provided buffer (n bytes).
    ///
    /// # Panics
    /// Panics in debug builds if `out.len() != N`.
    fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) {
        let result = Self::h(pk_seed, adrs, m1, m2);
        out.copy_from_slice(&result);
    }

    /// Tl into a caller-provided buffer (n bytes).
    ///
    /// # Panics
    /// Panics in debug builds if `out.len() != N`.
    fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]) {
        let result = Self::t_l(pk_seed, adrs, m);
        out.copy_from_slice(&result);
    }

    /// PRF into a caller-provided buffer (n bytes).
    ///
    /// Unlike [`prf`](Self::prf), this does NOT return `Zeroizing`.
    /// The caller is responsible for zeroizing `out` when it contains secret material.
    ///
    /// # Panics
    /// Panics in debug builds if `out.len() != N`.
    fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) {
        let result = Self::prf(pk_seed, sk_seed, adrs);
        out.copy_from_slice(&result);
    }
}
