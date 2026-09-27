//! Byte encoding and decoding for ML-KEM polynomials.
//!
//! This module implements FIPS 203 Algorithms 5 (ByteEncode) and 6 (ByteDecode)
//! for serializing polynomials to bytes and deserializing them back.
//!
//! The primary encoding used is d=12 (384 bytes for 256 coefficients),
//! which is used for public key (t) and secret key (s) polynomials.

#![allow(clippy::needless_range_loop)]

use crate::params::common::Q;
use crate::poly::{compress, Poly};
use crate::reduce::cond_reduce;
use subtle::{Choice, ConditionallySelectable, ConstantTimeLess};

/// Unpack two 12-bit coefficients from a 3-byte chunk (ByteDecode12).
///
/// Layout: `c0 = b0 | ((b1 & 0x0F) << 8)`, `c1 = (b1 >> 4) | (b2 << 4)`
#[inline]
fn unpack_12bit_coeffs(chunk: &[u8]) -> (u16, u16) {
    debug_assert_eq!(chunk.len(), 3);
    let b0 = chunk[0] as u16;
    let b1 = chunk[1] as u16;
    let b2 = chunk[2] as u16;
    let c0 = b0 | ((b1 & 0x0F) << 8);
    let c1 = (b1 >> 4) | (b2 << 4);
    (c0, c1)
}

/// Encode a polynomial to bytes using 12-bit coefficients.
///
/// Each coefficient is in [0, q-1] and is encoded as 12 bits.
/// 256 coefficients * 12 bits = 3072 bits = 384 bytes.
///
/// # Arguments
/// * `poly` - Polynomial with coefficients in [0, q-1]
///
/// # Returns
/// 384-byte encoded polynomial
pub fn poly_to_bytes(poly: &Poly) -> [u8; 384] {
    let mut bytes = [0u8; 384];

    for i in 0..128 {
        // Two coefficients -> three bytes
        let c0 = poly.coeffs[2 * i] as u16;
        let c1 = poly.coeffs[2 * i + 1] as u16;

        // Pack two 12-bit values into 3 bytes
        // c0 = [b0, b1[3:0]]
        // c1 = [b1[7:4], b2]
        bytes[3 * i] = c0 as u8;
        bytes[3 * i + 1] = ((c0 >> 8) | (c1 << 4)) as u8;
        bytes[3 * i + 2] = (c1 >> 4) as u8;
    }

    bytes
}

/// Decode bytes to a polynomial using 12-bit coefficients.
///
/// Decodes 384 bytes into 256 coefficients.
/// Coefficients are reduced modulo q (constant-time).
/// Panics if `bytes` is shorter than 384 bytes.
///
/// # Arguments
/// * `bytes` - 384-byte encoded polynomial
///
/// # Returns
/// Decoded polynomial with coefficients in [0, q-1]
pub fn poly_from_bytes(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();

    // Direct indexing: chunks_exact would divide the (public) length by 3,
    // leaving divide instructions in this secret-key decoder at some opt-levels.
    for i in 0..128 {
        let (c0, c1) = unpack_12bit_coeffs(&bytes[3 * i..3 * i + 3]);

        // Reduce mod q: redundant for ek inputs pre-validated by check_ek_modulus,
        // but necessary for the secret key in k_pke_decrypt. `% q` can compile
        // to a variable-latency divide; a 12-bit value is below 2q, so one
        // branchless conditional subtraction is exact.
        poly.coeffs[2 * i] = cond_reduce(c0 as i16);
        poly.coeffs[2 * i + 1] = cond_reduce(c1 as i16);
    }

    poly
}

/// Encode a message (32 bytes) as a polynomial.
///
/// Each bit of the message is expanded to a coefficient:
/// - 0 bit -> 0
/// - 1 bit -> (q+1)/2 = 1665 (rounded half of q)
///
/// This is used for encoding the message m in K-PKE encryption.
///
/// # Arguments
/// * `m` - 32-byte message
///
/// # Returns
/// Polynomial with coefficients in {0, 1665}
pub fn msg_to_poly(m: &[u8; 32]) -> Poly {
    const HALF_Q: i16 = (Q as i16 + 1) / 2; // 1665
    let mut poly = Poly::new();

    for i in 0..32 {
        for j in 0..8 {
            let bit = Choice::from((m[i] >> j) & 1);
            poly.coeffs[8 * i + j] = i16::conditional_select(&0, &HALF_Q, bit);
        }
    }

    poly
}

/// Decode a polynomial to a message (32 bytes).
///
/// Each coefficient is compressed to 1 bit:
/// - Coefficients closer to 0 -> 0 bit
/// - Coefficients closer to q/2 -> 1 bit
///
/// This is used for decoding the message m in K-PKE decryption.
///
/// # Arguments
/// * `poly` - Polynomial to decode
///
/// # Returns
/// 32-byte message
pub fn poly_to_msg(poly: &Poly) -> [u8; 32] {
    let mut m = [0u8; 32];

    for i in 0..32 {
        for j in 0..8 {
            m[i] |= (compress(poly.coeffs[8 * i + j], 1) as u8) << j;
        }
    }

    m
}

// --- Validation ---

/// Check that all 12-bit ByteDecode12-decoded coefficients in an encapsulation key are `< Q`.
///
/// FIPS 203 §7.2 (Algorithm 17) requires this type check on the encapsulation key
/// before encapsulation. The `t` portion of `ek` (excluding the 32-byte `rho`
/// suffix) is interpreted using the same ByteDecode12 unpacking as
/// [`poly_from_bytes`], yielding 12-bit decoded coefficients in the range
/// `[0, 2^12 - 1]`. This function enforces that each such decoded coefficient
/// satisfies `decoded < Q`. Values outside `[0, 2^12 - 1]` are not representable
/// via the encoding.
///
/// # Arguments
/// * `ek` - Full encapsulation key bytes: one or more 384-byte polynomials
///   followed by a 32-byte rho suffix (i.e., `n*384 + 32` with `n >= 1`)
///
/// # Returns
/// `true` if every 12-bit decoded coefficient in the `t` portion satisfies
/// `decoded < Q`, `false` otherwise.
pub(crate) fn check_ek_modulus(ek: &[u8]) -> bool {
    // ek must contain the 32-byte rho suffix plus at least one polynomial
    if ek.len() <= 32 {
        return false;
    }

    // Check t bytes only (exclude 32-byte rho suffix)
    let t_len = ek.len() - 32;

    // t portion must consist of whole 384-byte polynomials (K * 384 bytes)
    if t_len % 384 != 0 {
        return false;
    }

    let t_bytes = &ek[..t_len];
    // Constant-time coefficient scan: accumulate validity using subtle::Choice
    // to avoid leaking the position of any invalid coefficient via timing.
    // The early returns above on length/alignment are not secret-dependent.
    let mut all_valid = Choice::from(1u8);
    for chunk in t_bytes.chunks_exact(3) {
        let (c0, c1) = unpack_12bit_coeffs(chunk);
        all_valid &= c0.ct_lt(&Q);
        all_valid &= c1.ct_lt(&Q);
    }
    all_valid.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::common::N;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    #[test]
    fn test_poly_to_bytes_from_bytes_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i as i16 * 13) % (Q as i16);
        }

        let bytes = poly_to_bytes(&poly);
        let recovered = poly_from_bytes(&bytes);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], recovered.coeffs[i],
                "Mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_poly_to_bytes_from_bytes_zero() {
        let poly = Poly::new();
        let bytes = poly_to_bytes(&poly);
        let recovered = poly_from_bytes(&bytes);

        for i in 0..N {
            assert_eq!(recovered.coeffs[i], 0);
        }
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_poly_to_bytes_from_bytes_max() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (Q - 1) as i16;
        }

        let bytes = poly_to_bytes(&poly);
        let recovered = poly_from_bytes(&bytes);

        for i in 0..N {
            assert_eq!(recovered.coeffs[i], (Q - 1) as i16);
        }
    }

    #[test]
    fn test_poly_from_bytes_all_12bit_values() {
        // Two passes so every 12-bit value lands in both the c0 and c1 slot.
        for offset in [0usize, 1] {
            for base in (0..4096).step_by(N) {
                let value = |i: usize| ((base + i + offset) % 4096) as u16;
                let mut bytes = [0u8; 384];
                for i in 0..128 {
                    let (c0, c1) = (value(2 * i), value(2 * i + 1));
                    bytes[3 * i] = c0 as u8;
                    bytes[3 * i + 1] = ((c0 >> 8) | (c1 << 4)) as u8;
                    bytes[3 * i + 2] = (c1 >> 4) as u8;
                }
                let poly = poly_from_bytes(&bytes);
                for i in 0..N {
                    assert_eq!(
                        poly.coeffs[i],
                        (value(i) % Q) as i16,
                        "ByteDecode12 of {}",
                        value(i)
                    );
                }
            }
        }
    }

    #[test]
    fn test_poly_to_msg_exhaustive() {
        // FIPS 203 Compress_1: round(2x / q) mod 2 is 1 exactly for x in [833, 2496].
        let expected_bit = |x: i16| {
            let x = x.rem_euclid(Q as i16);
            (833..=2496).contains(&x) as u8
        };
        let min = -(Q as i16 - 1);
        let mut start = min;
        while start < Q as i16 {
            let mut poly = Poly::new();
            for i in 0..N {
                poly.coeffs[i] = (start + i as i16).min(Q as i16 - 1);
            }
            let m = poly_to_msg(&poly);
            for i in 0..N {
                let bit = (m[i / 8] >> (i % 8)) & 1;
                assert_eq!(
                    bit,
                    expected_bit(poly.coeffs[i]),
                    "poly_to_msg bit for {}",
                    poly.coeffs[i]
                );
            }
            start = start.saturating_add(N as i16);
        }
    }

    #[test]
    fn test_poly_to_msg_boundaries() {
        for (x, bit) in [
            (0i16, 0u8),
            (832, 0),
            (833, 1),
            (1664, 1),
            (1665, 1),
            (2496, 1),
            (2497, 0),
            (3328, 0),
            (-1, 0),
            (-832, 0),
            (-833, 1),
            (-1664, 1),
            (-3328, 0),
        ] {
            let mut poly = Poly::new();
            poly.coeffs[0] = x;
            assert_eq!(poly_to_msg(&poly)[0] & 1, bit, "poly_to_msg bit for {}", x);
        }
    }

    #[test]
    fn test_msg_to_poly_all_byte_values() {
        let half_q = ((Q as i16) + 1) / 2;
        for b in 0..=255u8 {
            let msg = [b; 32];
            let poly = msg_to_poly(&msg);
            for i in 0..N {
                let bit = ((b >> (i % 8)) & 1) as i16;
                assert_eq!(poly.coeffs[i], bit * half_q, "msg_to_poly byte {:#04x}", b);
            }
            assert_eq!(poly_to_msg(&poly), msg);
        }
    }

    #[test]
    fn test_msg_to_poly_to_msg_roundtrip() {
        let msg = [0x42u8; 32];
        let poly = msg_to_poly(&msg);
        let recovered = poly_to_msg(&poly);
        assert_eq!(msg, recovered);
    }

    #[test]
    fn test_msg_to_poly_all_zeros() {
        let msg = [0u8; 32];
        let poly = msg_to_poly(&msg);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], 0);
        }
    }

    #[test]
    fn test_msg_to_poly_all_ones() {
        let msg = [0xFFu8; 32];
        let poly = msg_to_poly(&msg);
        let half_q = ((Q as i16) + 1) / 2;

        for i in 0..N {
            assert_eq!(poly.coeffs[i], half_q);
        }
    }

    #[test]
    fn test_check_ek_modulus_valid() {
        // Build a valid ek: K=3 polynomials (3*384 bytes) + 32-byte rho
        let ek_size = 3 * 384 + 32;
        let t_size = 3 * 384;

        // All coefficients = 0 (valid)
        let ek_zeros = vec![0u8; ek_size];
        assert!(check_ek_modulus(&ek_zeros));

        // All coefficients = Q-1 = 3328 = 0xD00
        // c0 = b0 | ((b1 & 0x0F) << 8) = 0x00 | (0x0D << 8) = 0xD00
        // c1 = (b1 >> 4) | (b2 << 4) = 0x00 | (0xD0 << 4) = 0xD00
        let mut ek_max = vec![0u8; ek_size];
        for chunk in ek_max[..t_size].chunks_exact_mut(3) {
            chunk[0] = 0x00;
            chunk[1] = 0x0D;
            chunk[2] = 0xD0;
        }
        assert!(check_ek_modulus(&ek_max));
    }

    #[test]
    fn test_check_ek_modulus_invalid() {
        let ek_size = 3 * 384 + 32;
        let t_size = 3 * 384;

        // c0 = Q = 3329 = 0xD01
        // b0 = 0x01, b1 low nibble = 0x0D
        let mut ek = vec![0u8; ek_size];
        ek[0] = 0x01;
        ek[1] = 0x0D;
        assert!(!check_ek_modulus(&ek));

        // c1 = Q = 3329 = 0xD01
        // c1 = (b1 >> 4) | (b2 << 4)
        // Need (b1 >> 4) | (b2 << 4) = 0xD01
        // b1 high nibble = 0x10 (>> 4 = 0x01), b2 = 0xD0 (<< 4 = 0xD00)
        // 0x01 | 0xD00 = 0xD01 = 3329
        let mut ek2 = vec![0u8; ek_size];
        ek2[1] = 0x10;
        ek2[2] = 0xD0;
        assert!(!check_ek_modulus(&ek2));

        // c0 = 0xFFF = 4095 (max 12-bit value, well above Q)
        let mut ek3 = vec![0u8; ek_size];
        ek3[0] = 0xFF;
        ek3[1] = 0x0F;
        assert!(!check_ek_modulus(&ek3));

        // c1 = 0xFFF = 4095 (max 12-bit value in second coefficient position)
        // c1 = (b1 >> 4) | (b2 << 4) = 0xFFF
        // b1 high nibble = 0xF0 (>> 4 = 0x0F), b2 = 0xFF (<< 4 = 0xFF0)
        // 0x0F | 0xFF0 = 0xFFF = 4095
        let mut ek3b = vec![0u8; ek_size];
        ek3b[1] = 0xF0;
        ek3b[2] = 0xFF;
        assert!(!check_ek_modulus(&ek3b));

        // Invalid coefficient in the middle of the ek
        let mut ek4 = vec![0u8; ek_size];
        let mid = t_size / 2;
        let mid_aligned = mid - (mid % 3); // align to chunk boundary
        ek4[mid_aligned] = 0x01;
        ek4[mid_aligned + 1] = 0x0D;
        assert!(!check_ek_modulus(&ek4));

        // Degenerate inputs: too short, rho-only, or non-polynomial-aligned
        assert!(!check_ek_modulus(&[]));
        assert!(!check_ek_modulus(&[0u8; 31]));
        assert!(!check_ek_modulus(&[0u8; 32])); // rho-only, no t portion
        assert!(!check_ek_modulus(&[0u8; 35])); // t_len=3, not a multiple of 384
        assert!(!check_ek_modulus(&[0u8; 32 + 383])); // one byte short of a polynomial
        assert!(!check_ek_modulus(&[0u8; 32 + 384 + 1])); // one byte over one polynomial
    }
}
