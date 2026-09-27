//! SHA2-based hash function implementations for SLH-DSA.
//!
//! This module provides hash function implementations for the SHA2-based
//! SLH-DSA parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f).
//!
//! FIPS 205, Section 11.2 defines the SHA2-based hash functions:
//! - Category 1 (128-bit, n=16): All functions use SHA-256
//! - Category 3/5 (192/256-bit, n=24/32): F and PRF use SHA-256,
//!   H, T_l, PRFmsg, and Hmsg use SHA-512

use crate::address::Address;
use crate::hash::HashSuite;
use crate::wipe_sha2;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

#[cfg(all(test, not(feature = "std")))]
use alloc::{vec, vec::Vec};

/// SHA2-based hash suite for 128-bit security (n=16).
pub struct Sha2_128Hash;

/// SHA2-based hash suite for 192-bit security (n=24).
pub struct Sha2_192Hash;

/// SHA2-based hash suite for 256-bit security (n=32).
pub struct Sha2_256Hash;

/// Compress the 32-byte ADRS to the 22-byte ADRSc used by the SHA2 variants.
///
/// FIPS 205, Section 11.2: ADRSc = ADRS\[3\] || ADRS\[8:16\] || ADRS\[19\] || ADRS\[20:32\].
fn adrs_compress(adrs: &Address) -> [u8; 22] {
    let bytes = adrs.as_bytes();
    let mut compressed = [0u8; 22];
    compressed[0] = bytes[3];
    compressed[1..9].copy_from_slice(&bytes[8..16]);
    compressed[9] = bytes[19];
    compressed[10..22].copy_from_slice(&bytes[20..32]);
    compressed
}

/// MGF1 mask generation function, generic over hash algorithm.
///
/// FIPS 205, Section 11.2:
/// - MGF1-SHA-256 for 128-bit security (`mgf1::<Sha256>`)
/// - MGF1-SHA-512 for 192/256-bit security (`mgf1::<Sha512>`)
///
/// Only used in tests now that Hmsg is implemented purely via `mgf1_to`.
#[cfg(test)]
fn mgf1<D: Digest + Clone>(seed_parts: &[&[u8]], mask_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; mask_len];
    mgf1_to::<D>(&mut output, seed_parts);
    output
}

/// Buffer-write MGF1 mask generation function, generic over hash algorithm.
///
/// # Panics
///
/// Panics if `out.len()` needs more than `u32::MAX` hash blocks. This is a
/// genuine runtime bound rather than a parameter-set check: MGF1's counter is
/// 4 bytes wide by definition (FIPS 205, Section 11.2), so the limit cannot be
/// lifted. No FIPS 205 parameter set comes close to it.
fn mgf1_to<D: Digest + Clone>(out: &mut [u8], seed_parts: &[&[u8]]) {
    let hash_len = <D as Digest>::output_size();
    let num_blocks = out.len().div_ceil(hash_len);
    let Ok(num_blocks_u32) = u32::try_from(num_blocks) else {
        panic!("MGF1 counter overflow: mask_len too large");
    };

    // Pre-hash all seed parts once, then clone for each block
    let mut base_hasher = D::new();
    for part in seed_parts {
        base_hasher.update(part);
    }

    let mut written = 0;
    for i in 0..num_blocks_u32 {
        let mut hasher = base_hasher.clone();
        hasher.update(i.to_be_bytes());
        let block = hasher.finalize();
        let remaining = out.len() - written;
        let count = remaining.min(hash_len);
        out[written..written + count].copy_from_slice(&block[..count]);
        written += count;
    }
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

fn secret_sha256_trunc_to(
    out: &mut [u8],
    pk_seed: &[u8],
    padding: &[u8],
    adrs: &Address,
    m: &[u8],
) {
    let adrs_c = adrs_compress(adrs);
    let mut hasher = wipe_sha2::Sha256::new();
    hasher.update(pk_seed);
    hasher.update(padding);
    hasher.update(&adrs_c);
    hasher.update(m);
    hasher.finalize_into(out);
}

// =============================================================================
// 128-bit security: All functions use SHA-256
// =============================================================================

impl Sha2_128Hash {
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

    fn prf_msg_to(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) {
        debug_assert_eq!(out.len(), 16);
        wipe_sha2::hmac_sha256_into(out, sk_prf, &[opt_rand, message]);
    }

    fn prf_msg_parts_to(
        out: &mut [u8],
        sk_prf: &[u8],
        opt_rand: &[u8],
        message_prefix: &[u8],
        message: &[u8],
    ) {
        debug_assert_eq!(out.len(), 16);
        wipe_sha2::hmac_sha256_into(out, sk_prf, &[opt_rand, message_prefix, message]);
    }

    fn h_msg_to(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8]) {
        use sha2::digest::Update;
        let mut inner_hash = Sha256::new()
            .chain(r)
            .chain(pk_seed)
            .chain(pk_root)
            .chain(message)
            .finalize();
        mgf1_to::<Sha256>(out, &[r, pk_seed, &inner_hash]);
        inner_hash.zeroize();
    }

    fn h_msg_parts_to(
        out: &mut [u8],
        r: &[u8],
        pk_seed: &[u8],
        pk_root: &[u8],
        message_prefix: &[u8],
        message: &[u8],
    ) {
        use sha2::digest::Update;
        let mut inner_hash = Sha256::new()
            .chain(r)
            .chain(pk_seed)
            .chain(pk_root)
            .chain(message_prefix)
            .chain(message)
            .finalize();
        mgf1_to::<Sha256>(out, &[r, pk_seed, &inner_hash]);
        inner_hash.zeroize();
    }

    fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
        debug_assert_eq!(out.len(), 16);
        secret_sha256_trunc_to(out, pk_seed, &PADDING_SHA256_N16, adrs, m1);
    }

    fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m1, m2]);
    }

    fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]) {
        Self::sha256_hash_trunc_n_to(out, pk_seed, adrs, &[m]);
    }

    fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) {
        debug_assert_eq!(out.len(), 16);
        secret_sha256_trunc_to(out, pk_seed, &PADDING_SHA256_N16, adrs, sk_seed);
    }
}

// =============================================================================
// 192/256-bit security: F and PRF use SHA-256, H/T_l/PRFmsg/Hmsg use SHA-512
// FIPS 205, Section 11.2
// =============================================================================

/// Macro to implement HashSuite for SHA2 192/256-bit security levels.
///
/// Per FIPS 205 Section 11.2:
/// - F, PRF: SHA-256 with 64-byte block padding (toByte(0, 64-n))
/// - H, T_l: SHA-512 with 128-byte block padding (toByte(0, 128-n))
/// - PRFmsg: HMAC-SHA-512
/// - Hmsg: MGF1-SHA-512 with inner SHA-512
macro_rules! impl_sha2_cat35_hash_suite {
    ($name:ident, $n:expr, $padding_256:ident, $padding_512:ident) => {
        impl $name {
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

            fn prf_msg_to(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) {
                debug_assert_eq!(out.len(), $n);
                wipe_sha2::hmac_sha512_into(out, sk_prf, &[opt_rand, message]);
            }

            fn prf_msg_parts_to(
                out: &mut [u8],
                sk_prf: &[u8],
                opt_rand: &[u8],
                message_prefix: &[u8],
                message: &[u8],
            ) {
                debug_assert_eq!(out.len(), $n);
                wipe_sha2::hmac_sha512_into(out, sk_prf, &[opt_rand, message_prefix, message]);
            }

            fn h_msg_to(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8]) {
                use sha2::digest::Update;
                let mut inner_hash = Sha512::new()
                    .chain(r)
                    .chain(pk_seed)
                    .chain(pk_root)
                    .chain(message)
                    .finalize();
                mgf1_to::<Sha512>(out, &[r, pk_seed, &inner_hash]);
                inner_hash.zeroize();
            }

            fn h_msg_parts_to(
                out: &mut [u8],
                r: &[u8],
                pk_seed: &[u8],
                pk_root: &[u8],
                message_prefix: &[u8],
                message: &[u8],
            ) {
                use sha2::digest::Update;
                let mut inner_hash = Sha512::new()
                    .chain(r)
                    .chain(pk_seed)
                    .chain(pk_root)
                    .chain(message_prefix)
                    .chain(message)
                    .finalize();
                mgf1_to::<Sha512>(out, &[r, pk_seed, &inner_hash]);
                inner_hash.zeroize();
            }

            fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
                // F uses SHA-256
                debug_assert_eq!(out.len(), $n);
                secret_sha256_trunc_to(out, pk_seed, &$padding_256, adrs, m1);
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
                debug_assert_eq!(out.len(), $n);
                secret_sha256_trunc_to(out, pk_seed, &$padding_256, adrs, sk_seed);
            }
        }
    };
}

impl_sha2_cat35_hash_suite!(Sha2_192Hash, 24, PADDING_SHA256_N24, PADDING_SHA512_N24);
impl_sha2_cat35_hash_suite!(Sha2_256Hash, 32, PADDING_SHA256_N32, PADDING_SHA512_N32);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;
    type HmacSha512 = Hmac<Sha512>;

    #[test]
    fn test_adrs_compress_wots_hash_layout() {
        let adrs = Address::wots_hash(
            0x0102_0304,
            0x0506_0708_0910_1112,
            0xAABB_CCDD,
            0x1122_3344,
            0x5566_7788,
        );
        assert_eq!(
            adrs_compress(&adrs),
            [
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ]
        );
    }

    #[test]
    fn test_adrs_compress_fors_tree_layout() {
        let adrs = Address::fors_tree(3, 9, 0x0102_0304, 0x0506_0708, 0x090A_0B0C);
        assert_eq!(
            adrs_compress(&adrs),
            [
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x03, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ]
        );
    }

    #[test]
    fn test_mgf1_sha256() {
        let seed = b"test seed";
        let output = mgf1::<Sha256>(&[seed.as_slice()], 64);
        assert_eq!(output.len(), 64);

        // Verify determinism
        assert_eq!(output, mgf1::<Sha256>(&[seed.as_slice()], 64));

        // Verify prefix property (longer output starts with shorter output)
        let output_32 = mgf1::<Sha256>(&[seed.as_slice()], 32);
        assert_eq!(&output[..32], &output_32[..]);

        // Verify multi-part seed produces correct concatenation
        let part1 = b"test ";
        let part2 = b"seed";
        let output_multi = mgf1::<Sha256>(&[part1.as_slice(), part2.as_slice()], 64);
        assert_eq!(output, output_multi);
    }

    #[test]
    fn test_mgf1_sha512() {
        let seed = b"test seed";
        let output = mgf1::<Sha512>(&[seed.as_slice()], 128);
        assert_eq!(output.len(), 128);

        // Verify determinism
        assert_eq!(output, mgf1::<Sha512>(&[seed.as_slice()], 128));

        // Verify prefix property
        let output_64 = mgf1::<Sha512>(&[seed.as_slice()], 64);
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
