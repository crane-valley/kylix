//! SHA2-based hash function implementations for SLH-DSA.
//!
//! This module provides hash function implementations for the SHA2-based
//! SLH-DSA parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f).
//!
//! FIPS 205, Section 10.2 defines the SHA2-based hash functions:
//! - Category 1 (128-bit, n=16): All functions use SHA-256
//! - Category 3/5 (192/256-bit, n=24/32): F and PRF use SHA-256,
//!   H, T_l, PRFmsg, and Hmsg use SHA-512

use crate::address::{Address, AdrsType};
use crate::hash::HashSuite;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// SHA2-based hash suite for 128-bit security (n=16).
pub struct Sha2_128Hash;

/// SHA2-based hash suite for 192-bit security (n=24).
pub struct Sha2_192Hash;

/// SHA2-based hash suite for 256-bit security (n=32).
pub struct Sha2_256Hash;

// Address type constants for readable match patterns (FIPS 205, Table 1)
const WOTS_HASH: u32 = AdrsType::WotsHash as u32;
const WOTS_PK: u32 = AdrsType::WotsPk as u32;
const WOTS_PRF: u32 = AdrsType::WotsPrf as u32;
const FORS_PRF: u32 = AdrsType::ForsPrf as u32;

/// Compress 32-byte ADRS to 22-byte ADRS^c for SHA2 variants.
///
/// FIPS 205, Section 10.2, Table 3: The compressed address ADRSc is formed by:
/// - Bytes 0-3: Layer address (4 bytes)
/// - Bytes 4-11: Tree address lower 64 bits (8 bytes)
/// - Bytes 12-15: Type (4 bytes)
/// - Bytes 16-19: Key pair address (WOTS types) or tree height (other types)
/// - Bytes 20-21: Bits 16-31 of chain address (WOTS_PRF) or hash/tree index (others)
fn adrs_compress(adrs: &Address) -> [u8; 22] {
    let bytes = adrs.as_bytes();
    let adrs_type = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let mut compressed = [0u8; 22];

    // Layer address (bytes 0-3)
    compressed[0..4].copy_from_slice(&bytes[0..4]);

    // Tree address lower 64 bits (bytes 8-15 of original -> bytes 4-11 of compressed)
    compressed[4..12].copy_from_slice(&bytes[8..16]);

    // Type (bytes 16-19 of original -> bytes 12-15 of compressed)
    compressed[12..16].copy_from_slice(&bytes[16..20]);

    // Bytes 16-19: key pair address (WOTS types and FORS_PRF) or tree height (TREE, FORS_TREE, FORS_PK)
    // FIPS 205 Table 3: FORS_PRF uses keypair, not tree height
    match adrs_type {
        WOTS_HASH | WOTS_PK | WOTS_PRF | FORS_PRF => {
            compressed[16..20].copy_from_slice(&bytes[20..24]); // keypair
        }
        _ => compressed[16..20].copy_from_slice(&bytes[24..28]), // height
    }

    // Bytes 20-21: bits 16-31 of the relevant field
    // WOTS_PRF only: chain address at offset 24, use bytes 26-27
    // Others (including FORS_PRF): tree index at offset 28, use bytes 30-31
    match adrs_type {
        WOTS_PRF => compressed[20..22].copy_from_slice(&bytes[26..28]), // chain bits 16-31
        _ => compressed[20..22].copy_from_slice(&bytes[30..32]),        // index bits 16-31
    }

    compressed
}

/// MGF1 mask generation function using SHA-256.
///
/// FIPS 205, Section 10.2: MGF1-SHA-256 for 128-bit security.
fn mgf1_sha256(seed_parts: &[&[u8]], mask_len: usize) -> Vec<u8> {
    const HASH_LEN: usize = 32; // SHA-256 output size
    let num_blocks = mask_len.div_ceil(HASH_LEN);
    let mut output = Vec::with_capacity(num_blocks * HASH_LEN);

    // Pre-hash all seed parts once, then clone for each block
    let mut base_hasher = Sha256::new();
    for part in seed_parts {
        base_hasher.update(part);
    }

    for i in 0..num_blocks as u32 {
        let mut hasher = base_hasher.clone();
        hasher.update(i.to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
    }

    output.truncate(mask_len);
    output
}

/// MGF1 mask generation function using SHA-512.
///
/// FIPS 205, Section 10.2: MGF1-SHA-512 for 192/256-bit security.
fn mgf1_sha512(seed_parts: &[&[u8]], mask_len: usize) -> Vec<u8> {
    const HASH_LEN: usize = 64; // SHA-512 output size
    let num_blocks = mask_len.div_ceil(HASH_LEN);
    let mut output = Vec::with_capacity(num_blocks * HASH_LEN);

    let mut base_hasher = Sha512::new();
    for part in seed_parts {
        base_hasher.update(part);
    }

    for i in 0..num_blocks as u32 {
        let mut hasher = base_hasher.clone();
        hasher.update(i.to_be_bytes());
        output.extend_from_slice(&hasher.finalize());
    }

    output.truncate(mask_len);
    output
}

/// Zero padding for SHA-256 block alignment (64-byte block): toByte(0, 64-n).
/// Used by F and PRF for all security levels.
const PADDING_SHA256_N16: [u8; 48] = [0u8; 48]; // 64 - 16, for n=16 (128-bit)
const PADDING_SHA256_N24: [u8; 40] = [0u8; 40]; // 64 - 24, for n=24 (192-bit)
const PADDING_SHA256_N32: [u8; 32] = [0u8; 32]; // 64 - 32, for n=32 (256-bit)

/// Zero padding for SHA-512 block alignment (128-byte block): toByte(0, 128-n).
/// Used by H and T_l for 192/256-bit security levels.
const PADDING_SHA512_N24: [u8; 104] = [0u8; 104]; // 128 - 24, for n=24 (192-bit)
const PADDING_SHA512_N32: [u8; 96] = [0u8; 96]; // 128 - 32, for n=32 (256-bit)

// =============================================================================
// 128-bit security: All functions use SHA-256
// =============================================================================

impl Sha2_128Hash {
    /// Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M...))
    fn sha256_hash_trunc_n(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]]) -> Vec<u8> {
        let adrs_c = adrs_compress(adrs);
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        hasher.update(PADDING_SHA256_N16);
        hasher.update(adrs_c);
        for m in ms {
            hasher.update(m);
        }
        let mut hash = hasher.finalize();
        let out = hash[..16].to_vec();
        hash.zeroize();
        out
    }

    fn sha256_hash_trunc_n_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, ms: &[&[u8]]) {
        debug_assert_eq!(out.len(), 16);
        let adrs_c = adrs_compress(adrs);
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        hasher.update(PADDING_SHA256_N16);
        hasher.update(adrs_c);
        for m in ms {
            hasher.update(m);
        }
        let mut hash = hasher.finalize();
        out.copy_from_slice(&hash[..16]);
        hash.zeroize();
    }
}

impl HashSuite for Sha2_128Hash {
    const N: usize = 16;

    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>> {
        // PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || SK.seed))
        Zeroizing::new(Self::sha256_hash_trunc_n(pk_seed, adrs, &[sk_seed]))
    }

    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
        // PRFmsg = Trunc_n(HMAC-SHA-256(SK.prf, OptRand || M))
        let mut mac = HmacSha256::new_from_slice(sk_prf).expect("HMAC accepts any key length");
        mac.update(opt_rand);
        mac.update(message);
        let result = mac.finalize().into_bytes();
        Zeroizing::new(result[..16].to_vec())
    }

    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8], out_len: usize) -> Vec<u8> {
        // Hmsg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
        use sha2::digest::Update;
        let inner_hash = Sha256::new()
            .chain(r)
            .chain(pk_seed)
            .chain(pk_root)
            .chain(message)
            .finalize();
        mgf1_sha256(&[r, pk_seed, &inner_hash], out_len)
    }

    fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8> {
        Self::sha256_hash_trunc_n(pk_seed, adrs, &[m1])
    }

    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        Self::sha256_hash_trunc_n(pk_seed, adrs, &[m1, m2])
    }

    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        Self::sha256_hash_trunc_n(pk_seed, adrs, &[m])
    }

    fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m1]);
    }

    fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m1, m2]);
    }

    fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m]);
    }

    fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[sk_seed]);
    }
}

// =============================================================================
// 192/256-bit security: F and PRF use SHA-256, H/T_l/PRFmsg/Hmsg use SHA-512
// FIPS 205, Section 10.2
// =============================================================================

/// Macro to implement HashSuite for SHA2 192/256-bit security levels.
///
/// Per FIPS 205 Section 10.2:
/// - F, PRF: SHA-256 with 64-byte block padding (toByte(0, 64-n))
/// - H, T_l: SHA-512 with 128-byte block padding (toByte(0, 128-n))
/// - PRFmsg: HMAC-SHA-512
/// - Hmsg: MGF1-SHA-512 with inner SHA-512
macro_rules! impl_sha2_cat35_hash_suite {
    ($name:ident, $n:expr, $padding_256:ident, $padding_512:ident) => {
        impl $name {
            /// SHA-256 hash with padding and truncation (for F and PRF).
            fn sha256_hash_trunc_n(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]]) -> Vec<u8> {
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&$padding_256);
                hasher.update(&adrs_c);
                for m in ms {
                    hasher.update(m);
                }
                let mut hash = hasher.finalize();
                let out = hash[..$n].to_vec();
                hash.zeroize();
                out
            }

            /// Buffer-write variant of sha256_hash_trunc_n (for F and PRF).
            fn sha256_hash_trunc_n_to(
                out: &mut [u8],
                pk_seed: &[u8],
                adrs: &Address,
                ms: &[&[u8]],
            ) {
                debug_assert_eq!(out.len(), $n);
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha256::new();
                hasher.update(pk_seed);
                hasher.update(&$padding_256);
                hasher.update(&adrs_c);
                for m in ms {
                    hasher.update(m);
                }
                let mut hash = hasher.finalize();
                out.copy_from_slice(&hash[..$n]);
                hash.zeroize();
            }

            /// SHA-512 hash with padding and truncation (for H and T_l).
            fn sha512_hash_trunc_n(pk_seed: &[u8], adrs: &Address, ms: &[&[u8]]) -> Vec<u8> {
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha512::new();
                hasher.update(pk_seed);
                hasher.update(&$padding_512);
                hasher.update(&adrs_c);
                for m in ms {
                    hasher.update(m);
                }
                let mut hash = hasher.finalize();
                let out = hash[..$n].to_vec();
                hash.zeroize();
                out
            }

            /// Buffer-write variant of sha512_hash_trunc_n (for H and T_l).
            fn sha512_hash_trunc_n_to(
                out: &mut [u8],
                pk_seed: &[u8],
                adrs: &Address,
                ms: &[&[u8]],
            ) {
                debug_assert_eq!(out.len(), $n);
                let adrs_c = adrs_compress(adrs);
                let mut hasher = Sha512::new();
                hasher.update(pk_seed);
                hasher.update(&$padding_512);
                hasher.update(&adrs_c);
                for m in ms {
                    hasher.update(m);
                }
                let mut hash = hasher.finalize();
                out.copy_from_slice(&hash[..$n]);
                hash.zeroize();
            }
        }

        impl HashSuite for $name {
            const N: usize = $n;

            fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Zeroizing<Vec<u8>> {
                // PRF uses SHA-256 for all security levels
                Zeroizing::new(Self::sha256_hash_trunc_n(pk_seed, adrs, &[sk_seed]))
            }

            fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
                // PRFmsg = Trunc_n(HMAC-SHA-512(SK.prf, OptRand || M))
                let mut mac =
                    HmacSha512::new_from_slice(sk_prf).expect("HMAC accepts any key length");
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
                // Hmsg = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
                use sha2::digest::Update;
                let inner_hash = Sha512::new()
                    .chain(r)
                    .chain(pk_seed)
                    .chain(pk_root)
                    .chain(message)
                    .finalize();
                mgf1_sha512(&[r, pk_seed, &inner_hash], out_len)
            }

            fn f(pk_seed: &[u8], adrs: &Address, m1: &[u8]) -> Vec<u8> {
                // F uses SHA-256 for all security levels
                Self::sha256_hash_trunc_n(pk_seed, adrs, &[m1])
            }

            fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
                // H uses SHA-512 for category 3/5
                Self::sha512_hash_trunc_n(pk_seed, adrs, &[m1, m2])
            }

            fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
                // T_l uses SHA-512 for category 3/5
                Self::sha512_hash_trunc_n(pk_seed, adrs, &[m])
            }

            fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
                // F uses SHA-256
                Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m1]);
            }

            fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) {
                // H uses SHA-512 for category 3/5
                Self::sha512_hash_trunc_n_to(out, pk_seed, adrs, &[m1, m2]);
            }

            fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]) {
                // T_l uses SHA-512 for category 3/5
                Self::sha512_hash_trunc_n_to(out, pk_seed, adrs, &[m]);
            }

            fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) {
                // PRF uses SHA-256
                Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[sk_seed]);
            }
        }
    };
}

impl_sha2_cat35_hash_suite!(Sha2_192Hash, 24, PADDING_SHA256_N24, PADDING_SHA512_N24);
impl_sha2_cat35_hash_suite!(Sha2_256Hash, 32, PADDING_SHA256_N32, PADDING_SHA512_N32);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_adrs_compress_wots_hash() {
        // WOTS_HASH (type 0): uses keypair (bytes 20-23) and hash (bytes 30-31)
        let adrs = Address::wots_hash(0x0102_0304, 0x0506_0708_0910_1112, 0xAABB_CCDD, 5, 7);
        let compressed = adrs_compress(&adrs);

        assert_eq!(compressed.len(), 22);
        // Layer address (bytes 0-3)
        assert_eq!(&compressed[0..4], &[0x01, 0x02, 0x03, 0x04]);
        // Tree address lower 64 bits (bytes 4-11)
        assert_eq!(
            &compressed[4..12],
            &[0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12]
        );
        // Type (bytes 12-15) = WOTS_HASH = 0
        assert_eq!(&compressed[12..16], &[0, 0, 0, 0]);
        // Key pair (bytes 16-19) for WOTS types
        assert_eq!(&compressed[16..20], &[0xAA, 0xBB, 0xCC, 0xDD]);
        // Hash address bits 16-31 (bytes 20-21) - hash=7, bits 16-31 = 0x0007
        assert_eq!(&compressed[20..22], &[0x00, 0x07]);
    }

    #[test]
    fn test_adrs_compress_wots_prf() {
        // WOTS_PRF (type 5): uses keypair (bytes 20-23) and chain (bytes 26-27)
        let adrs = Address::wots_prf(1, 2, 0x1234_5678, 0xABCD_EF01);
        let compressed = adrs_compress(&adrs);

        // Type (bytes 12-15) = WOTS_PRF = 5
        assert_eq!(&compressed[12..16], &[0, 0, 0, 5]);
        // Key pair (bytes 16-19) for WOTS types
        assert_eq!(&compressed[16..20], &[0x12, 0x34, 0x56, 0x78]);
        // Chain address bits 16-31 (bytes 20-21) - chain=0xABCDEF01, bits 16-31 = 0xEF01
        assert_eq!(&compressed[20..22], &[0xEF, 0x01]);
    }

    #[test]
    fn test_adrs_compress_tree() {
        // TREE (type 2): uses height (bytes 24-27) and index (bytes 30-31)
        let adrs = Address::tree_node(1, 2, 0x1111_2222, 0x3333_4444);
        let compressed = adrs_compress(&adrs);

        // Type (bytes 12-15) = TREE = 2
        assert_eq!(&compressed[12..16], &[0, 0, 0, 2]);
        // Tree height (bytes 16-19) for non-WOTS types
        assert_eq!(&compressed[16..20], &[0x11, 0x11, 0x22, 0x22]);
        // Tree index bits 16-31 (bytes 20-21) - index=0x33334444, bits 16-31 = 0x4444
        assert_eq!(&compressed[20..22], &[0x44, 0x44]);
    }

    #[test]
    fn test_adrs_compress_fors_prf() {
        // FORS_PRF (type 6): uses keypair (bytes 20-23) for compressed bytes 16-19,
        // and tree index bits 16-31 (bytes 30-31) for compressed bytes 20-21
        // FIPS 205 Table 3: FORS_PRF has keypair at offset 20, tree index at offset 28
        let adrs = Address::fors_prf(0, 0, 0x1234_5678, 0xAAAA_BBBB, 0xCCCC_DDDD);
        let compressed = adrs_compress(&adrs);

        // Type (bytes 12-15) = FORS_PRF = 6
        assert_eq!(&compressed[12..16], &[0, 0, 0, 6]);
        // Keypair (bytes 16-19) for FORS_PRF - keypair=0x12345678
        assert_eq!(&compressed[16..20], &[0x12, 0x34, 0x56, 0x78]);
        // Tree index bits 16-31 (bytes 20-21) - index=0xCCCCDDDD, bits 16-31 = 0xDDDD
        assert_eq!(&compressed[20..22], &[0xDD, 0xDD]);
    }

    #[test]
    fn test_fors_prf_keypair_separation() {
        // Verify that different keypairs produce different ADRS^c for FORS_PRF
        let adrs1 = Address::fors_prf(0, 0, 0, 0, 0); // keypair = 0
        let adrs2 = Address::fors_prf(0, 0, 1, 0, 0); // keypair = 1

        let compressed1 = adrs_compress(&adrs1);
        let compressed2 = adrs_compress(&adrs2);

        // The compressed addresses should differ in bytes 16-19
        assert_ne!(compressed1, compressed2);
        assert_ne!(&compressed1[16..20], &compressed2[16..20]);
    }

    #[test]
    fn test_wots_prf_chain_separation() {
        // Verify that different chain indices produce different ADRS^c
        let adrs1 = Address::wots_prf(0, 0, 0, 0); // chain = 0
        let adrs2 = Address::wots_prf(0, 0, 0, 1); // chain = 1

        let compressed1 = adrs_compress(&adrs1);
        let compressed2 = adrs_compress(&adrs2);

        // The compressed addresses should differ in bytes 20-21
        assert_ne!(compressed1, compressed2);
        assert_ne!(&compressed1[20..22], &compressed2[20..22]);
    }

    #[test]
    fn test_mgf1_sha256() {
        let seed = b"test seed";
        let output = mgf1_sha256(&[seed.as_slice()], 64);
        assert_eq!(output.len(), 64);

        // Verify determinism
        assert_eq!(output, mgf1_sha256(&[seed.as_slice()], 64));

        // Verify prefix property (longer output starts with shorter output)
        let output_32 = mgf1_sha256(&[seed.as_slice()], 32);
        assert_eq!(&output[..32], &output_32[..]);

        // Verify multi-part seed produces correct concatenation
        let part1 = b"test ";
        let part2 = b"seed";
        let output_multi = mgf1_sha256(&[part1.as_slice(), part2.as_slice()], 64);
        assert_eq!(output, output_multi);
    }

    #[test]
    fn test_mgf1_sha512() {
        let seed = b"test seed";
        let output = mgf1_sha512(&[seed.as_slice()], 128);
        assert_eq!(output.len(), 128);

        // Verify determinism
        assert_eq!(output, mgf1_sha512(&[seed.as_slice()], 128));

        // Verify prefix property
        let output_64 = mgf1_sha512(&[seed.as_slice()], 64);
        assert_eq!(&output[..64], &output_64[..]);
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

    #[test]
    fn test_192_h_uses_sha512() {
        // Verify that 192-bit H uses SHA-512 by independently computing the expected value
        let pk_seed = [0u8; 24];
        let adrs = Address::new();
        let m1 = [1u8; 24];
        let m2 = [2u8; 24];

        let h_out = Sha2_192Hash::h(&pk_seed, &adrs, &m1, &m2);
        assert_eq!(h_out.len(), 24);

        // Independently compute: Trunc_24(SHA-512(PK.seed || toByte(0, 128-24) || ADRSc || M1 || M2))
        let adrs_c = adrs_compress(&adrs);
        let expected_sha512 = {
            let mut hasher = Sha512::new();
            hasher.update(pk_seed);
            hasher.update(PADDING_SHA512_N24);
            hasher.update(adrs_c);
            hasher.update(m1);
            hasher.update(m2);
            let hash = hasher.finalize();
            hash[..24].to_vec()
        };
        assert_eq!(
            h_out, expected_sha512,
            "H should match independent SHA-512 computation"
        );

        // Also verify it differs from what SHA-256 would produce
        let sha256_result = {
            let mut hasher = Sha256::new();
            hasher.update(pk_seed);
            hasher.update(PADDING_SHA256_N24);
            hasher.update(adrs_c);
            hasher.update(m1);
            hasher.update(m2);
            let hash = hasher.finalize();
            hash[..24].to_vec()
        };
        assert_ne!(
            h_out, sha256_result,
            "H should differ from SHA-256 computation"
        );
    }

    #[test]
    fn test_256_prf_msg_uses_hmac_sha512() {
        let sk_prf = [0u8; 32];
        let opt_rand = [1u8; 32];
        let message = b"test message";

        let out = Sha2_256Hash::prf_msg(&sk_prf, &opt_rand, message);
        assert_eq!(out.len(), 32);

        // Independently compute: Trunc_32(HMAC-SHA-512(SK.prf, OptRand || M))
        let expected = {
            let mut mac = HmacSha512::new_from_slice(&sk_prf).expect("HMAC accepts any key length");
            mac.update(&opt_rand);
            mac.update(message);
            let result = mac.finalize().into_bytes();
            result[..32].to_vec()
        };
        assert_eq!(
            *out, expected,
            "PRFmsg should match independent HMAC-SHA-512 computation"
        );

        // Also verify it differs from HMAC-SHA-256
        let hmac256_result = {
            let mut mac = HmacSha256::new_from_slice(&sk_prf).expect("HMAC accepts any key length");
            mac.update(&opt_rand);
            mac.update(message);
            let result = mac.finalize().into_bytes();
            result[..32].to_vec()
        };
        assert_ne!(
            *out, hmac256_result,
            "PRFmsg should differ from HMAC-SHA-256 computation"
        );
    }
}
