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
use alloc::{vec, vec::Vec};

/// Maximum value of N across all SLH-DSA parameter sets (256-bit security = 32 bytes).
/// Used for stack buffer sizing in `_to` buffer-write variants.
pub const MAX_N: usize = 32;

/// Maximum Hmsg output length across the built-in SLH-DSA parameter sets.
///
/// The largest shipped digest is for the SHA2-256f parameter set:
/// `ceil(35*9/8) + ceil((68-4)/8) + ceil(4/8) = 49` bytes.
/// Larger const-generic experiments fall back to heap-backed scratch space
/// in the signing and verification paths.
pub const MAX_M_DIGEST_BYTES: usize = 49;

/// Hash function suite trait for SLH-DSA.
///
/// Implementations of this trait provide the complete set of hash functions
/// required for a specific SLH-DSA variant (SHAKE or SHA2 based).
///
/// The buffer-write `*_to` methods form the required interface: they write into
/// a caller-provided buffer and so let callers keep secret material out of
/// intermediate heap allocations. The allocating `Vec`-returning methods are
/// provided defaults layered on top of them, so an implementor only has to get
/// the streaming bodies right once.
pub trait HashSuite {
    /// Security parameter n (hash output length in bytes).
    /// - 16 for 128-bit security
    /// - 24 for 192-bit security
    /// - 32 for 256-bit security
    const N: usize;

    // --- Required buffer-write interface ---

    /// F into a caller-provided buffer (n bytes).
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2).
    ///
    /// # Arguments
    /// * `out` - Destination buffer, exactly `N` bytes
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m1` - Input message (n bytes)
    fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]);

    /// H into a caller-provided buffer (n bytes).
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2).
    ///
    /// # Arguments
    /// * `out` - Destination buffer, exactly `N` bytes
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m1` - Left child (n bytes)
    /// * `m2` - Right child (n bytes)
    fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]);

    /// Tl into a caller-provided buffer (n bytes).
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2).
    ///
    /// # Arguments
    /// * `out` - Destination buffer, exactly `N` bytes
    /// * `pk_seed` - Public seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    /// * `m` - Input message (l*n bytes where l is the number of inputs)
    fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]);

    /// PRF into a caller-provided buffer (n bytes).
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2).
    ///
    /// Unlike [`prf`](Self::prf), this does NOT return `Zeroizing`.
    /// The caller is responsible for zeroizing `out` when it contains secret material.
    ///
    /// # Arguments
    /// * `out` - Destination buffer, exactly `N` bytes
    /// * `pk_seed` - Public seed (n bytes)
    /// * `sk_seed` - Secret seed (n bytes)
    /// * `adrs` - Address structure for domain separation
    fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address);

    /// PRFmsg into a caller-provided buffer (n bytes).
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2).
    ///
    /// Unlike [`prf_msg`](Self::prf_msg), this does NOT return `Zeroizing`.
    /// The caller is responsible for zeroizing `out` when it contains secret material.
    ///
    /// # Arguments
    /// * `out` - Destination buffer, exactly `N` bytes
    /// * `sk_prf` - Secret PRF key (n bytes)
    /// * `opt_rand` - Optional randomness (n bytes, can be PK.seed for deterministic signing)
    /// * `message` - Message to sign
    fn prf_msg_to(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], message: &[u8]);

    /// Hmsg into a caller-provided buffer.
    ///
    /// FIPS 205, Section 10.1 (SHAKE) or 10.2 (SHA2). The digest length is
    /// taken from `out.len()`.
    ///
    /// # Arguments
    /// * `out` - Destination buffer; its length selects the digest length
    /// * `r` - Randomizer (n bytes)
    /// * `pk_seed` - Public seed (n bytes)
    /// * `pk_root` - Public root (n bytes)
    /// * `message` - Message to sign
    fn h_msg_to(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8]);

    // --- Streaming multi-part variants ---
    // Defaults concatenate; implementations should override with a streaming
    // body so callers never have to materialize prefix || message.

    /// PRFmsg over two message slices without requiring callers to concatenate them.
    fn prf_msg_parts_to(
        out: &mut [u8],
        sk_prf: &[u8],
        opt_rand: &[u8],
        message_prefix: &[u8],
        message: &[u8],
    ) {
        if message_prefix.is_empty() {
            Self::prf_msg_to(out, sk_prf, opt_rand, message);
            return;
        }

        let mut combined = Vec::with_capacity(message_prefix.len() + message.len());
        combined.extend_from_slice(message_prefix);
        combined.extend_from_slice(message);
        Self::prf_msg_to(out, sk_prf, opt_rand, &combined);
    }

    /// Hmsg over two message slices without requiring callers to concatenate them.
    fn h_msg_parts_to(
        out: &mut [u8],
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        message_prefix: &[u8],
        message: &[u8],
    ) {
        if message_prefix.is_empty() {
            Self::h_msg_to(out, r, pk_seed, pk_root, message);
            return;
        }

        let mut combined = Vec::with_capacity(message_prefix.len() + message.len());
        combined.extend_from_slice(message_prefix);
        combined.extend_from_slice(message);
        Self::h_msg_to(out, r, pk_seed, pk_root, &combined);
    }

    // --- Allocating convenience wrappers ---
    // Provided defaults over the required `*_to` methods; never override these
    // with a second hash body, or a fix can land in only one of the two copies.

    /// PRF: Generate n-byte pseudorandom output for secret key material.
    ///
    /// Used for: WOTS+ and FORS secret key generation
    ///
    /// # Returns
    /// n-byte pseudorandom output wrapped in `Zeroizing` for automatic memory cleanup
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0u8; Self::N]);
        Self::prf_to(&mut out, pk_seed, sk_seed, adrs);
        out
    }

    /// PRFmsg: Generate n-byte randomizer for message signing.
    ///
    /// Used for: Generating the randomizer R in signature generation
    ///
    /// # Returns
    /// n-byte randomizer wrapped in `Zeroizing` for automatic memory cleanup
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0u8; Self::N]);
        Self::prf_msg_to(&mut out, sk_prf, opt_rand, message);
        out
    }

    /// Hmsg: Generate message digest for FORS signing.
    ///
    /// Used for: Generating the digest that determines FORS indices
    ///
    /// # Returns
    /// Message digest of `out_len` bytes
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8], out_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; out_len];
        Self::h_msg_to(&mut out, r, pk_seed, pk_root, message);
        out
    }

    /// F: Chaining function for WOTS+.
    ///
    /// # Returns
    /// n-byte hash output
    fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Self::N];
        Self::f_to(&mut out, pk_seed, adrs, m1);
        out
    }

    /// H: Two-to-one hash function.
    ///
    /// # Returns
    /// n-byte hash output
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Self::N];
        Self::h_to(&mut out, pk_seed, adrs, m1, m2);
        out
    }

    /// Tl: Multi-input hash function.
    ///
    /// # Returns
    /// n-byte hash output
    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Self::N];
        Self::t_l_to(&mut out, pk_seed, adrs, m);
        out
    }
}
