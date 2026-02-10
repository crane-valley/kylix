//! Byte encoding and decoding for ML-KEM polynomials.
//!
//! This module implements FIPS 203 Algorithms 5 (ByteEncode) and 6 (ByteDecode)
//! for serializing polynomials to bytes and deserializing them back.
//!
//! The primary encoding used is d=12 (384 bytes for 256 coefficients),
//! which is used for public key (t) and secret key (s) polynomials.

// Internal helper functions for byte encoding; not all variants are used by every parameter set.
#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::params::common::Q;
use crate::poly::Poly;
use subtle::{Choice, ConstantTimeLess};

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
/// Coefficients are reduced modulo q.
///
/// # Arguments
/// * `bytes` - 384-byte encoded polynomial
///
/// # Returns
/// Decoded polynomial with coefficients in [0, q-1]
pub fn poly_from_bytes(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();

    // Decode exactly 128 coefficient pairs (256 coefficients) from 384 bytes.
    // Use .take(128) to bound the iteration to one polynomial even if the
    // input slice is longer than 384 bytes.
    for (i, chunk) in bytes.chunks_exact(3).take(128).enumerate() {
        let (c0, c1) = unpack_12bit_coeffs(chunk);

        // Reduce mod q — redundant for ek inputs pre-validated by check_ek_modulus,
        // but necessary for other callers (e.g., secret key deserialization in k_pke_decrypt).
        poly.coeffs[2 * i] = (c0 % Q) as i16;
        poly.coeffs[2 * i + 1] = (c1 % Q) as i16;
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
    let mut poly = Poly::new();
    let half_q = ((Q as i16) + 1) / 2; // 1665

    for i in 0..32 {
        for j in 0..8 {
            let bit = (m[i] >> j) & 1;
            poly.coeffs[8 * i + j] = if bit == 1 { half_q } else { 0 };
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
    let half_q = (Q as i16) / 2; // 1664

    for i in 0..32 {
        for j in 0..8 {
            // Compress coefficient to 1 bit
            // round(2 * c / q) mod 2
            let c = poly.coeffs[8 * i + j];
            // Normalize to [0, q-1]
            let c = if c < 0 { c + Q as i16 } else { c };
            // Check if closer to q/2 than to 0 or q
            let bit = if c > half_q / 2 && c < Q as i16 - half_q / 2 {
                1u8
            } else {
                0u8
            };
            m[i] |= bit << j;
        }
    }

    m
}

/// Generic byte encoding for d-bit coefficients.
///
/// Encodes 256 coefficients using d bits each, producing 32*d bytes.
///
/// # Arguments
/// * `poly` - Polynomial to encode
/// * `d` - Bits per coefficient (1, 4, 5, 10, 11, or 12)
/// * `out` - Output buffer (must have length >= 32*d)
pub fn byte_encode(poly: &Poly, d: usize, out: &mut [u8]) {
    match d {
        1 => byte_encode_1(poly, out),
        4 => byte_encode_4(poly, out),
        5 => byte_encode_5(poly, out),
        10 => byte_encode_10(poly, out),
        11 => byte_encode_11(poly, out),
        12 => {
            let bytes = poly_to_bytes(poly);
            out[..384].copy_from_slice(&bytes);
        }
        _ => panic!(
            "Unsupported d value: {} (supported: 1, 4, 5, 10, 11, 12)",
            d
        ),
    }
}

/// Generic byte decoding for d-bit coefficients.
///
/// Decodes 32*d bytes into 256 coefficients.
///
/// # Arguments
/// * `bytes` - Input bytes (must have length >= 32*d)
/// * `d` - Bits per coefficient (1, 4, 5, 10, 11, or 12)
///
/// # Returns
/// Decoded polynomial
pub fn byte_decode(bytes: &[u8], d: usize) -> Poly {
    match d {
        1 => byte_decode_1(bytes),
        4 => byte_decode_4(bytes),
        5 => byte_decode_5(bytes),
        10 => byte_decode_10(bytes),
        11 => byte_decode_11(bytes),
        12 => poly_from_bytes(bytes),
        _ => panic!(
            "Unsupported d value: {} (supported: 1, 4, 5, 10, 11, 12)",
            d
        ),
    }
}

// d=1: 32 bytes for 256 coefficients (1 bit each)
fn byte_encode_1(poly: &Poly, out: &mut [u8]) {
    for i in 0..32 {
        let mut byte = 0u8;
        for j in 0..8 {
            let c = poly.coeffs[8 * i + j];
            // Compress to 1 bit: round(2*c/q) mod 2
            let c = if c < 0 { c + Q as i16 } else { c };
            let bit = ((((c as u32) << 1) + (Q as u32) / 2) / (Q as u32)) & 1;
            byte |= (bit as u8) << j;
        }
        out[i] = byte;
    }
}

fn byte_decode_1(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();
    let half_q = ((Q as i16) + 1) / 2;

    for i in 0..32 {
        for j in 0..8 {
            let bit = (bytes[i] >> j) & 1;
            poly.coeffs[8 * i + j] = if bit == 1 { half_q } else { 0 };
        }
    }

    poly
}

// d=4: 128 bytes for 256 coefficients (4 bits each)
fn byte_encode_4(poly: &Poly, out: &mut [u8]) {
    for i in 0..128 {
        let c0 = poly.coeffs[2 * i] as u8;
        let c1 = poly.coeffs[2 * i + 1] as u8;
        out[i] = (c0 & 0x0F) | (c1 << 4);
    }
}

fn byte_decode_4(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();
    for i in 0..128 {
        poly.coeffs[2 * i] = (bytes[i] & 0x0F) as i16;
        poly.coeffs[2 * i + 1] = (bytes[i] >> 4) as i16;
    }
    poly
}

// d=5: 160 bytes for 256 coefficients (5 bits each)
fn byte_encode_5(poly: &Poly, out: &mut [u8]) {
    for i in 0..32 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = (poly.coeffs[8 * i + j] & 0x1F) as u8;
        }
        out[5 * i] = t[0] | (t[1] << 5);
        out[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        out[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
        out[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        out[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
    }
}

fn byte_decode_5(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();
    for i in 0..32 {
        let b = &bytes[5 * i..5 * i + 5];
        poly.coeffs[8 * i] = (b[0] & 0x1F) as i16;
        poly.coeffs[8 * i + 1] = (((b[0] >> 5) | (b[1] << 3)) & 0x1F) as i16;
        poly.coeffs[8 * i + 2] = ((b[1] >> 2) & 0x1F) as i16;
        poly.coeffs[8 * i + 3] = (((b[1] >> 7) | (b[2] << 1)) & 0x1F) as i16;
        poly.coeffs[8 * i + 4] = (((b[2] >> 4) | (b[3] << 4)) & 0x1F) as i16;
        poly.coeffs[8 * i + 5] = ((b[3] >> 1) & 0x1F) as i16;
        poly.coeffs[8 * i + 6] = (((b[3] >> 6) | (b[4] << 2)) & 0x1F) as i16;
        poly.coeffs[8 * i + 7] = (b[4] >> 3) as i16;
    }
    poly
}

// d=10: 320 bytes for 256 coefficients (10 bits each)
fn byte_encode_10(poly: &Poly, out: &mut [u8]) {
    for i in 0..64 {
        let mut t = [0u16; 4];
        for j in 0..4 {
            t[j] = (poly.coeffs[4 * i + j] & 0x3FF) as u16;
        }
        out[5 * i] = t[0] as u8;
        out[5 * i + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
        out[5 * i + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
        out[5 * i + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
        out[5 * i + 4] = (t[3] >> 2) as u8;
    }
}

fn byte_decode_10(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();
    for i in 0..64 {
        let b = &bytes[5 * i..5 * i + 5];
        poly.coeffs[4 * i] = ((b[0] as u16) | ((b[1] as u16 & 0x03) << 8)) as i16;
        poly.coeffs[4 * i + 1] = (((b[1] >> 2) as u16) | ((b[2] as u16 & 0x0F) << 6)) as i16;
        poly.coeffs[4 * i + 2] = (((b[2] >> 4) as u16) | ((b[3] as u16 & 0x3F) << 4)) as i16;
        poly.coeffs[4 * i + 3] = (((b[3] >> 6) as u16) | ((b[4] as u16) << 2)) as i16;
    }
    poly
}

// d=11: 352 bytes for 256 coefficients (11 bits each)
fn byte_encode_11(poly: &Poly, out: &mut [u8]) {
    for i in 0..32 {
        let mut t = [0u16; 8];
        for j in 0..8 {
            t[j] = (poly.coeffs[8 * i + j] & 0x7FF) as u16;
        }
        out[11 * i] = t[0] as u8;
        out[11 * i + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
        out[11 * i + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
        out[11 * i + 3] = (t[2] >> 2) as u8;
        out[11 * i + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
        out[11 * i + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
        out[11 * i + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
        out[11 * i + 7] = (t[5] >> 1) as u8;
        out[11 * i + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
        out[11 * i + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
        out[11 * i + 10] = (t[7] >> 3) as u8;
    }
}

fn byte_decode_11(bytes: &[u8]) -> Poly {
    let mut poly = Poly::new();
    for i in 0..32 {
        let b = &bytes[11 * i..11 * i + 11];
        poly.coeffs[8 * i] = ((b[0] as u16) | ((b[1] as u16 & 0x07) << 8)) as i16;
        poly.coeffs[8 * i + 1] = (((b[1] >> 3) as u16) | ((b[2] as u16 & 0x3F) << 5)) as i16;
        poly.coeffs[8 * i + 2] =
            (((b[2] >> 6) as u16) | ((b[3] as u16) << 2) | ((b[4] as u16 & 0x01) << 10)) as i16;
        poly.coeffs[8 * i + 3] = (((b[4] >> 1) as u16) | ((b[5] as u16 & 0x0F) << 7)) as i16;
        poly.coeffs[8 * i + 4] = (((b[5] >> 4) as u16) | ((b[6] as u16 & 0x7F) << 4)) as i16;
        poly.coeffs[8 * i + 5] =
            (((b[6] >> 7) as u16) | ((b[7] as u16) << 1) | ((b[8] as u16 & 0x03) << 9)) as i16;
        poly.coeffs[8 * i + 6] = (((b[8] >> 2) as u16) | ((b[9] as u16 & 0x1F) << 6)) as i16;
        poly.coeffs[8 * i + 7] = (((b[9] >> 5) as u16) | ((b[10] as u16) << 3)) as i16;
    }
    poly
}

// --- Validation ---

/// Check that all 12-bit coefficients in an encapsulation key are in [0, q-1].
///
/// FIPS 203 §7.2 (Algorithm 17) requires this type check on the encapsulation key
/// before encapsulation. Each pair of 12-bit coefficients is unpacked from the
/// t portion of ek (excluding the 32-byte rho suffix) and checked against Q.
/// Uses the same ByteDecode12 unpacking as [`poly_from_bytes`].
///
/// # Arguments
/// * `ek` - Full encapsulation key bytes: one or more 384-byte polynomials
///   followed by a 32-byte rho suffix (i.e., `n*384 + 32` with `n >= 1`)
///
/// # Returns
/// `true` if all coefficients are valid (< Q), `false` otherwise
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
    fn test_byte_encode_decode_d4_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i % 16) as i16;
        }

        let mut bytes = [0u8; 128];
        byte_encode(&poly, 4, &mut bytes);
        let recovered = byte_decode(&bytes, 4);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i], "Mismatch at {}", i);
        }
    }

    #[test]
    fn test_byte_encode_decode_d5_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i % 32) as i16;
        }

        let mut bytes = [0u8; 160];
        byte_encode(&poly, 5, &mut bytes);
        let recovered = byte_decode(&bytes, 5);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i], "Mismatch at {}", i);
        }
    }

    #[test]
    fn test_byte_encode_decode_d10_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i % 1024) as i16;
        }

        let mut bytes = [0u8; 320];
        byte_encode(&poly, 10, &mut bytes);
        let recovered = byte_decode(&bytes, 10);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i], "Mismatch at {}", i);
        }
    }

    #[test]
    fn test_byte_encode_decode_d11_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i % 2048) as i16;
        }

        let mut bytes = [0u8; 352];
        byte_encode(&poly, 11, &mut bytes);
        let recovered = byte_decode(&bytes, 11);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i], "Mismatch at {}", i);
        }
    }

    #[test]
    fn test_byte_encode_decode_d12_roundtrip() {
        let mut poly = Poly::new();
        for i in 0..N {
            poly.coeffs[i] = (i as i16 * 13) % (Q as i16);
        }

        let mut bytes = [0u8; 384];
        byte_encode(&poly, 12, &mut bytes);
        let recovered = byte_decode(&bytes, 12);

        for i in 0..N {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i], "Mismatch at {}", i);
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
