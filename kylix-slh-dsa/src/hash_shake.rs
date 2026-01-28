//! SHAKE-based hash function implementations for SLH-DSA.
//!
//! This module provides hash function implementations for the SHAKE-based
//! SLH-DSA parameter sets (SHAKE-128s/f, SHAKE-192s/f, SHAKE-256s/f).
//!
//! FIPS 205, Section 10.1 defines the SHAKE-based hash functions.

use crate::address::Address;
use crate::hash::HashSuite;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec;

/// SHAKE256-based hash suite for 128-bit security (n=16).
pub struct Shake128Hash;

/// SHAKE256-based hash suite for 192-bit security (n=24).
pub struct Shake192Hash;

/// SHAKE256-based hash suite for 256-bit security (n=32).
pub struct Shake256Hash;

/// Internal helper to compute SHAKE256 hash with variable output length.
/// Only used in tests now that all HashSuite methods use streaming API.
#[cfg(test)]
fn shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; out_len];
    reader.read(&mut output);
    output
}

/// Macro to implement HashSuite for a specific security level.
macro_rules! impl_shake_hash_suite {
    ($name:ident, $n:expr) => {
        impl HashSuite for $name {
            const N: usize = $n;

            fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>> {
                // PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
                // Use streaming API to avoid copying secret key to heap
                let mut hasher = Shake256::default();
                hasher.update(pk_seed);
                hasher.update(adrs.as_bytes());
                hasher.update(sk_seed);
                let mut reader = hasher.finalize_xof();
                let mut output = Zeroizing::new(vec![0u8; $n]);
                reader.read(&mut output);
                output
            }

            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
                // PRFmsg(SK.prf, OptRand, M) = SHAKE256(SK.prf || OptRand || M, 8n)
                // Use streaming API to avoid copying secret key to heap
                let mut hasher = Shake256::default();
                hasher.update(sk_prf);
                hasher.update(opt_rand);
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = Zeroizing::new(vec![0u8; $n]);
                reader.read(&mut output);
                output
            }

            fn h_msg(
                r: &[u8],
                pk_seed: &[u8],
                pk_root: &[u8],
                message: &[u8],
                out_len: usize,
            ) -> Vec<u8> {
                // Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8*out_len)
                // Use streaming API to avoid intermediate heap allocation
                let mut hasher = Shake256::default();
                hasher.update(r);
                hasher.update(pk_seed);
                hasher.update(pk_root);
                hasher.update(message);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; out_len];
                reader.read(&mut output);
                output
            }

            fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8> {
                // F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, 8n)
                // Use streaming API to avoid intermediate heap allocation
                let mut hasher = Shake256::default();
                hasher.update(pk_seed);
                hasher.update(adrs.as_bytes());
                hasher.update(m1);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; $n];
                reader.read(&mut output);
                output
            }

            fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
                // H(PK.seed, ADRS, M1 || M2) = SHAKE256(PK.seed || ADRS || M1 || M2, 8n)
                // Use streaming API to avoid intermediate heap allocation
                let mut hasher = Shake256::default();
                hasher.update(pk_seed);
                hasher.update(adrs.as_bytes());
                hasher.update(m1);
                hasher.update(m2);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; $n];
                reader.read(&mut output);
                output
            }

            fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
                // Tl(PK.seed, ADRS, M) = SHAKE256(PK.seed || ADRS || M, 8n)
                // Use streaming API to avoid intermediate heap allocation
                let mut hasher = Shake256::default();
                hasher.update(pk_seed);
                hasher.update(adrs.as_bytes());
                hasher.update(m);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; $n];
                reader.read(&mut output);
                output
            }
        }
    };
}

impl_shake_hash_suite!(Shake128Hash, 16);
impl_shake_hash_suite!(Shake192Hash, 24);
impl_shake_hash_suite!(Shake256Hash, 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_basic() {
        let output = shake256(b"test", 32);
        assert_eq!(output.len(), 32);
        // Verify determinism
        assert_eq!(output, shake256(b"test", 32));
    }

    #[test]
    fn test_prf_determinism() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs = Address::new();

        let out1 = Shake128Hash::prf(&pk_seed, &sk_seed, &adrs);
        let out2 = Shake128Hash::prf(&pk_seed, &sk_seed, &adrs);

        assert_eq!(out1.len(), 16);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_different_adrs() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let adrs2 = Address::wots_hash(0, 0, 0, 0, 1);

        let out1 = Shake128Hash::prf(&pk_seed, &sk_seed, &adrs1);
        let out2 = Shake128Hash::prf(&pk_seed, &sk_seed, &adrs2);

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_f_output_length() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        let m1 = [0u8; 16];

        let out = Shake128Hash::f(&pk_seed, &adrs, &m1);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_h_combines_inputs() {
        let pk_seed = [0u8; 24];
        let adrs = Address::new();
        let m1 = [1u8; 24];
        let m2 = [2u8; 24];

        let out = Shake192Hash::h(&pk_seed, &adrs, &m1, &m2);
        assert_eq!(out.len(), 24);

        // Swapping m1 and m2 should give different result
        let out_swapped = Shake192Hash::h(&pk_seed, &adrs, &m2, &m1);
        assert_ne!(out, out_swapped);
    }

    #[test]
    fn test_h_msg_variable_output() {
        let r = [0u8; 32];
        let pk_seed = [1u8; 32];
        let pk_root = [2u8; 32];
        let message = b"test message";

        let out_32 = Shake256Hash::h_msg(&r, &pk_seed, &pk_root, message, 32);
        let out_64 = Shake256Hash::h_msg(&r, &pk_seed, &pk_root, message, 64);

        assert_eq!(out_32.len(), 32);
        assert_eq!(out_64.len(), 64);
        // First 32 bytes should match
        assert_eq!(&out_32[..], &out_64[..32]);
    }

    #[test]
    fn test_t_l_compression() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        // Compress 35 * 16 = 560 bytes (WOTS+ len = 35 for 128-bit)
        let m = vec![0u8; 35 * 16];

        let out = Shake128Hash::t_l(&pk_seed, &adrs, &m);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_all_security_levels() {
        let adrs = Address::new();

        // 128-bit
        let pk128 = [0u8; 16];
        let sk128 = [1u8; 16];
        assert_eq!(Shake128Hash::prf(&pk128, &sk128, &adrs).len(), 16);

        // 192-bit
        let pk192 = [0u8; 24];
        let sk192 = [1u8; 24];
        assert_eq!(Shake192Hash::prf(&pk192, &sk192, &adrs).len(), 24);

        // 256-bit
        let pk256 = [0u8; 32];
        let sk256 = [1u8; 32];
        assert_eq!(Shake256Hash::prf(&pk256, &sk256, &adrs).len(), 32);
    }
}
