//! SHA2-based hash function implementations for SLH-DSA.
//!
//! This module provides hash function implementations for the SHA2-based
//! SLH-DSA parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f).
//!
//! FIPS 205, Section 10.2 defines the SHA2-based hash functions.

use crate::address::Address;
use crate::hash::HashSuite;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

type HmacSha256 = Hmac<Sha256>;

/// SHA2-based hash suite for 128-bit security (n=16).
pub struct Sha2_128Hash;

/// SHA2-based hash suite for 192-bit security (n=24).
pub struct Sha2_192Hash;

/// SHA2-based hash suite for 256-bit security (n=32).
pub struct Sha2_256Hash;

/// Compress 32-byte ADRS to 22-byte ADRS^c for SHA2 variants.
///
/// FIPS 205, Section 10.2: The compressed address ADRSc is formed by:
/// - Bytes 0-3: Layer address (4 bytes)
/// - Bytes 4-11: Tree address (8 bytes, lower 64 bits)
/// - Bytes 12-15: Type (4 bytes)
/// - Bytes 16-19: Key pair / tree height (4 bytes)
/// - Bytes 20-21: Chain/hash / tree index (2 bytes, truncated)
fn adrs_compress(adrs: &Address) -> [u8; 22] {
    let bytes = adrs.as_bytes();
    let mut compressed = [0u8; 22];

    // Layer address (bytes 0-3)
    compressed[0..4].copy_from_slice(&bytes[0..4]);

    // Tree address lower 64 bits (bytes 8-15 of original -> bytes 4-11 of compressed)
    compressed[4..12].copy_from_slice(&bytes[8..16]);

    // Type (bytes 16-19 of original -> bytes 12-15 of compressed)
    compressed[12..16].copy_from_slice(&bytes[16..20]);

    // Key pair / tree height (bytes 20-23 of original -> bytes 16-19 of compressed)
    compressed[16..20].copy_from_slice(&bytes[20..24]);

    // Chain/hash / tree index (bytes 28-31 of original -> bytes 20-21 of compressed, truncated)
    // Take the lower 2 bytes (big-endian)
    compressed[20..22].copy_from_slice(&bytes[30..32]);

    compressed
}

/// MGF1 mask generation function using SHA-256.
///
/// FIPS 205, Section 10.2.1: MGF1-SHA-256 is used for variable-length outputs.
fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;

    while output.len() < mask_len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
        counter += 1;
    }

    output.truncate(mask_len);
    output
}

/// Macro to implement HashSuite for SHA2-based security levels.
macro_rules! impl_sha2_hash_suite {
    ($name:ident, $n:expr) => {
        impl HashSuite for $name {
            const N: usize = $n;

            fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>> {
                // PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || ADRS^c || SK.seed))
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&adrs_c);
                hasher.update(sk_seed);
                let hash = hasher.finalize();
                Zeroizing::new(hash[..$n].to_vec())
            }

            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
                // PRFmsg(SK.prf, OptRand, M) = Trunc_n(HMAC-SHA-256(SK.prf, OptRand || M))
                let mut mac =
                    HmacSha256::new_from_slice(sk_prf).expect("HMAC accepts any key length");
                mac.update(opt_rand);
                mac.update(message);
                let result = mac.finalize().into_bytes();
                Zeroizing::new(result[..$n].to_vec())
            }

            fn h_msg(
                r: &[u8],
                pk_seed: &[u8],
                pk_root: &[u8],
                message: &[u8],
                out_len: usize,
            ) -> Vec<u8> {
                // Hmsg(R, PK.seed, PK.root, M) =
                //   MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
                let mut inner_hasher = Sha256::new();
                inner_hasher.update(r);
                inner_hasher.update(pk_seed);
                inner_hasher.update(pk_root);
                inner_hasher.update(message);
                let inner_hash = inner_hasher.finalize();

                let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 32);
                seed.extend_from_slice(r);
                seed.extend_from_slice(pk_seed);
                seed.extend_from_slice(&inner_hash);

                mgf1_sha256(&seed, out_len)
            }

            fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8> {
                // F(PK.seed, ADRS, M1) = Trunc_n(SHA-256(PK.seed || ADRS^c || M1))
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&adrs_c);
                hasher.update(m1);
                let hash = hasher.finalize();
                hash[..$n].to_vec()
            }

            fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
                // H(PK.seed, ADRS, M1 || M2) = Trunc_n(SHA-256(PK.seed || ADRS^c || M1 || M2))
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&adrs_c);
                hasher.update(m1);
                hasher.update(m2);
                let hash = hasher.finalize();
                hash[..$n].to_vec()
            }

            fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
                // Tl(PK.seed, ADRS, M) = Trunc_n(SHA-256(PK.seed || ADRS^c || M))
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&adrs_c);
                hasher.update(m);
                let hash = hasher.finalize();
                hash[..$n].to_vec()
            }
        }
    };
}

impl_sha2_hash_suite!(Sha2_128Hash, 16);
impl_sha2_hash_suite!(Sha2_192Hash, 24);
impl_sha2_hash_suite!(Sha2_256Hash, 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adrs_compress() {
        let mut adrs = Address::new();
        adrs.set_layer(0x01020304);
        adrs.set_tree(0x0506070809101112);
        adrs.set_keypair(0x13141516);

        let compressed = adrs_compress(&adrs);
        assert_eq!(compressed.len(), 22);

        // Layer address (bytes 0-3)
        assert_eq!(&compressed[0..4], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_mgf1_sha256() {
        let seed = b"test seed";
        let output = mgf1_sha256(seed, 64);
        assert_eq!(output.len(), 64);

        // Verify determinism
        assert_eq!(output, mgf1_sha256(seed, 64));

        // Verify prefix property (longer output starts with shorter output)
        let output_32 = mgf1_sha256(seed, 32);
        assert_eq!(&output[..32], &output_32[..]);
    }

    #[test]
    fn test_prf_determinism() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs = Address::new();

        let out1 = Sha2_128Hash::prf(&pk_seed, &sk_seed, &adrs);
        let out2 = Sha2_128Hash::prf(&pk_seed, &sk_seed, &adrs);

        assert_eq!(out1.len(), 16);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_different_adrs() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let adrs2 = Address::wots_hash(0, 0, 0, 0, 1);

        let out1 = Sha2_128Hash::prf(&pk_seed, &sk_seed, &adrs1);
        let out2 = Sha2_128Hash::prf(&pk_seed, &sk_seed, &adrs2);

        assert_ne!(out1, out2);
    }

    #[test]
    fn test_prf_msg_uses_hmac() {
        let sk_prf = [0u8; 16];
        let opt_rand = [1u8; 16];
        let message = b"test message";

        let out = Sha2_128Hash::prf_msg(&sk_prf, &opt_rand, message);
        assert_eq!(out.len(), 16);

        // Different message should give different output
        let out2 = Sha2_128Hash::prf_msg(&sk_prf, &opt_rand, b"different message");
        assert_ne!(out, out2);
    }

    #[test]
    fn test_f_output_length() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        let m1 = [0u8; 16];

        let out = Sha2_128Hash::f(&pk_seed, &adrs, &m1);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_h_combines_inputs() {
        let pk_seed = [0u8; 24];
        let adrs = Address::new();
        let m1 = [1u8; 24];
        let m2 = [2u8; 24];

        let out = Sha2_192Hash::h(&pk_seed, &adrs, &m1, &m2);
        assert_eq!(out.len(), 24);

        // Swapping m1 and m2 should give different result
        let out_swapped = Sha2_192Hash::h(&pk_seed, &adrs, &m2, &m1);
        assert_ne!(out, out_swapped);
    }

    #[test]
    fn test_h_msg_variable_output() {
        let r = [0u8; 32];
        let pk_seed = [1u8; 32];
        let pk_root = [2u8; 32];
        let message = b"test message";

        let out_32 = Sha2_256Hash::h_msg(&r, &pk_seed, &pk_root, message, 32);
        let out_64 = Sha2_256Hash::h_msg(&r, &pk_seed, &pk_root, message, 64);

        assert_eq!(out_32.len(), 32);
        assert_eq!(out_64.len(), 64);
        // First 32 bytes should match (MGF1 prefix property)
        assert_eq!(&out_32[..], &out_64[..32]);
    }

    #[test]
    fn test_t_l_compression() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        // Compress 35 * 16 = 560 bytes (WOTS+ len = 35 for 128-bit)
        let m = vec![0u8; 35 * 16];

        let out = Sha2_128Hash::t_l(&pk_seed, &adrs, &m);
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn test_all_security_levels() {
        let adrs = Address::new();

        // 128-bit
        let pk128 = [0u8; 16];
        let sk128 = [1u8; 16];
        assert_eq!(Sha2_128Hash::prf(&pk128, &sk128, &adrs).len(), 16);

        // 192-bit
        let pk192 = [0u8; 24];
        let sk192 = [1u8; 24];
        assert_eq!(Sha2_192Hash::prf(&pk192, &sk192, &adrs).len(), 24);

        // 256-bit
        let pk256 = [0u8; 32];
        let sk256 = [1u8; 32];
        assert_eq!(Sha2_256Hash::prf(&pk256, &sk256, &adrs).len(), 32);
    }
}
