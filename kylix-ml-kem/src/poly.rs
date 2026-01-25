//! Polynomial operations for ML-KEM.
//!
//! This module provides the `Poly` struct representing polynomials in the ring
//! R_q = Z_q\[X\]/(X^256 + 1), along with arithmetic operations, compression,
//! and sampling functions as specified in FIPS 203.
//!
//! All operations are designed to be constant-time where necessary for security.

// Polynomial helpers include compression variants not used by all parameter sets.
#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_range_contains)]

use crate::ntt::{basemul, ZETAS};
use crate::params::common::{N, Q};
use crate::reduce::{barrett_reduce, barrett_reduce_full};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// A polynomial in R_q = Z_q\[X\]/(X^256 + 1).
///
/// Coefficients are stored as `i16` values. Depending on the context:
/// - Standard form: coefficients in [0, q-1]
/// - NTT form: coefficients represent evaluations at roots of unity
/// - Montgomery form: coefficients multiplied by R = 2^16 mod q
#[derive(Clone, Zeroize)]
pub struct Poly {
    /// 256 coefficients of the polynomial.
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i16; N] }
    }
}

impl Poly {
    /// Create a new zero polynomial.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a polynomial from a coefficient array.
    pub fn from_coeffs(coeffs: [i16; N]) -> Self {
        Self { coeffs }
    }
}

impl Poly {
    /// Constant-time conditional selection.
    ///
    /// Returns `a` if `choice` is 1, `b` if `choice` is 0.
    /// This operation is constant-time with respect to `choice`.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut r = Poly::default();
        for i in 0..N {
            // subtle's conditional_select returns first arg if choice=0, second if choice=1
            // We want: return a if choice=1, b if choice=0
            // So we swap the arguments
            r.coeffs[i] = i16::conditional_select(&b.coeffs[i], &a.coeffs[i], choice);
        }
        r
    }
}

impl ConstantTimeEq for Poly {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut eq = Choice::from(1u8);
        for i in 0..N {
            eq &= self.coeffs[i].ct_eq(&other.coeffs[i]);
        }
        eq
    }
}

// ============================================================================
// Polynomial Arithmetic
// ============================================================================

/// Add two polynomials coefficient-wise.
///
/// # Arguments
/// * `a` - First polynomial
/// * `b` - Second polynomial
///
/// # Returns
/// Sum polynomial (coefficients may exceed q, use `poly_reduce` if needed)
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::default();
    for i in 0..N {
        r.coeffs[i] = a.coeffs[i] + b.coeffs[i];
    }
    r
}

/// Add polynomial `b` to `a` in place.
pub fn poly_add_assign(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] += b.coeffs[i];
    }
}

/// Subtract two polynomials coefficient-wise.
///
/// # Arguments
/// * `a` - First polynomial
/// * `b` - Second polynomial
///
/// # Returns
/// Difference polynomial a - b
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::default();
    for i in 0..N {
        r.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }
    r
}

/// Subtract polynomial `b` from `a` in place.
pub fn poly_sub_assign(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] -= b.coeffs[i];
    }
}

/// Multiply two polynomials in NTT domain (point-wise multiplication).
///
/// Both inputs must already be in NTT domain. The result is also in NTT domain.
/// This performs base multiplication for each pair of coefficients.
///
/// # Arguments
/// * `a` - First polynomial in NTT domain
/// * `b` - Second polynomial in NTT domain
///
/// # Returns
/// Product polynomial in NTT domain
pub fn poly_basemul(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::default();
    // 64 pairs of basemuls, each pair using +zeta and -zeta
    for i in 0..64 {
        let zeta = ZETAS[64 + i];
        // First basemul with +zeta
        basemul(
            &mut r.coeffs[4 * i..4 * i + 2],
            &a.coeffs[4 * i..4 * i + 2],
            &b.coeffs[4 * i..4 * i + 2],
            zeta,
        );
        // Second basemul with -zeta
        basemul(
            &mut r.coeffs[4 * i + 2..4 * i + 4],
            &a.coeffs[4 * i + 2..4 * i + 4],
            &b.coeffs[4 * i + 2..4 * i + 4],
            -zeta,
        );
    }
    r
}

/// Accumulate product into result: r += a * b (in NTT domain).
pub fn poly_basemul_acc(r: &mut Poly, a: &Poly, b: &Poly) {
    #[cfg(feature = "simd")]
    {
        if crate::simd::poly_basemul_acc(&mut r.coeffs, &a.coeffs, &b.coeffs) {
            return;
        }
    }
    // Scalar fallback
    poly_basemul_acc_scalar(r, a, b);
}

/// Scalar implementation of polynomial basemul accumulate.
pub(crate) fn poly_basemul_acc_scalar(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..64 {
        let zeta = ZETAS[64 + i];
        let mut tmp = [0i16; 2];
        // First basemul with +zeta
        basemul(
            &mut tmp,
            &a.coeffs[4 * i..4 * i + 2],
            &b.coeffs[4 * i..4 * i + 2],
            zeta,
        );
        r.coeffs[4 * i] = r.coeffs[4 * i].wrapping_add(tmp[0]);
        r.coeffs[4 * i + 1] = r.coeffs[4 * i + 1].wrapping_add(tmp[1]);
        // Second basemul with -zeta
        basemul(
            &mut tmp,
            &a.coeffs[4 * i + 2..4 * i + 4],
            &b.coeffs[4 * i + 2..4 * i + 4],
            -zeta,
        );
        r.coeffs[4 * i + 2] = r.coeffs[4 * i + 2].wrapping_add(tmp[0]);
        r.coeffs[4 * i + 3] = r.coeffs[4 * i + 3].wrapping_add(tmp[1]);
    }
}

/// Reduce all coefficients of a polynomial using Barrett reduction.
pub fn poly_reduce(poly: &mut Poly) {
    for i in 0..N {
        poly.coeffs[i] = barrett_reduce(poly.coeffs[i]);
    }
}

/// Reduce all coefficients to canonical form [0, q-1].
pub fn poly_reduce_full(poly: &mut Poly) {
    for i in 0..N {
        poly.coeffs[i] = barrett_reduce_full(poly.coeffs[i]);
    }
}

/// Convert polynomial from Montgomery form to standard form.
///
/// Should be called after inv_ntt to convert back to standard coefficients.
pub fn poly_from_mont(poly: &mut Poly) {
    use crate::reduce::from_mont;
    for i in 0..N {
        poly.coeffs[i] = from_mont(poly.coeffs[i]);
    }
}

/// Convert polynomial to Montgomery form.
///
/// Should be called on polynomials sampled in NTT domain before multiplying
/// with other Montgomery-form polynomials.
pub fn poly_to_mont(poly: &mut Poly) {
    use crate::reduce::to_mont;
    for i in 0..N {
        poly.coeffs[i] = to_mont(poly.coeffs[i]);
    }
}

// ============================================================================
// Compression and Decompression (FIPS 203 Algorithms 4-5)
// ============================================================================

/// Compress a single coefficient.
///
/// Computes round(2^d / q * x) mod 2^d, mapping [0, q-1] to [0, 2^d - 1].
///
/// # Arguments
/// * `x` - Coefficient in [0, q-1]
/// * `d` - Number of bits for compression
///
/// # Returns
/// Compressed value in [0, 2^d - 1]
#[inline]
pub fn compress(x: i16, d: u32) -> u16 {
    // Ensure x is positive
    let x = if x < 0 { x + Q as i16 } else { x } as u32;
    // Compute round((x * 2^d) / q) mod 2^d
    // = floor((x * 2^d + q/2) / q) mod 2^d
    let shifted = (x << d) + (Q as u32 / 2);
    let result = shifted / (Q as u32);
    (result & ((1 << d) - 1)) as u16
}

/// Decompress a single coefficient.
///
/// Computes round(q / 2^d * y), mapping [0, 2^d - 1] to approximately [0, q-1].
///
/// # Arguments
/// * `y` - Compressed value in [0, 2^d - 1]
/// * `d` - Number of bits used in compression
///
/// # Returns
/// Decompressed coefficient (approximately original value)
#[inline]
pub fn decompress(y: u16, d: u32) -> i16 {
    // Compute round((y * q) / 2^d)
    // = floor((y * q + 2^(d-1)) / 2^d)
    let y = y as u32;
    let result = ((y * (Q as u32)) + (1 << (d - 1))) >> d;
    result as i16
}

/// Compress a polynomial and write to output buffer.
///
/// # Arguments
/// * `poly` - Polynomial to compress (must be in canonical form [0, q-1])
/// * `d` - Number of bits per coefficient
/// * `out` - Output buffer (must have sufficient space)
pub fn poly_compress(poly: &Poly, d: u32, out: &mut [u8]) {
    match d {
        4 => poly_compress_4(poly, out),
        5 => poly_compress_5(poly, out),
        10 => poly_compress_10(poly, out),
        11 => poly_compress_11(poly, out),
        _ => panic!(
            "Unsupported compression parameter d={} (supported: 4, 5, 10, 11)",
            d
        ),
    }
}

/// Decompress bytes into a polynomial.
///
/// # Arguments
/// * `bytes` - Compressed bytes
/// * `d` - Number of bits per coefficient
///
/// # Returns
/// Decompressed polynomial
pub fn poly_decompress(bytes: &[u8], d: u32) -> Poly {
    match d {
        4 => poly_decompress_4(bytes),
        5 => poly_decompress_5(bytes),
        10 => poly_decompress_10(bytes),
        11 => poly_decompress_11(bytes),
        _ => panic!(
            "Unsupported decompression parameter d={} (supported: 4, 5, 10, 11)",
            d
        ),
    }
}

// Compression with d=4 (128 bytes for 256 coefficients)
fn poly_compress_4(poly: &Poly, out: &mut [u8]) {
    for i in 0..128 {
        let t0 = compress(poly.coeffs[2 * i], 4) as u8;
        let t1 = compress(poly.coeffs[2 * i + 1], 4) as u8;
        out[i] = t0 | (t1 << 4);
    }
}

fn poly_decompress_4(bytes: &[u8]) -> Poly {
    let mut poly = Poly::default();
    for i in 0..128 {
        poly.coeffs[2 * i] = decompress((bytes[i] & 0x0F) as u16, 4);
        poly.coeffs[2 * i + 1] = decompress((bytes[i] >> 4) as u16, 4);
    }
    poly
}

// Compression with d=5 (160 bytes for 256 coefficients)
fn poly_compress_5(poly: &Poly, out: &mut [u8]) {
    for i in 0..32 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = compress(poly.coeffs[8 * i + j], 5) as u8;
        }
        // Pack 8 5-bit values into 5 bytes
        out[5 * i] = t[0] | (t[1] << 5);
        out[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        out[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
        out[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        out[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
    }
}

fn poly_decompress_5(bytes: &[u8]) -> Poly {
    let mut poly = Poly::default();
    for i in 0..32 {
        // Unpack 5 bytes into 8 5-bit values
        let b = &bytes[5 * i..5 * i + 5];
        poly.coeffs[8 * i] = decompress((b[0] & 0x1F) as u16, 5);
        poly.coeffs[8 * i + 1] = decompress(((b[0] >> 5) | ((b[1] & 0x03) << 3)) as u16, 5);
        poly.coeffs[8 * i + 2] = decompress(((b[1] >> 2) & 0x1F) as u16, 5);
        poly.coeffs[8 * i + 3] = decompress(((b[1] >> 7) | ((b[2] & 0x0F) << 1)) as u16, 5);
        poly.coeffs[8 * i + 4] = decompress(((b[2] >> 4) | ((b[3] & 0x01) << 4)) as u16, 5);
        poly.coeffs[8 * i + 5] = decompress(((b[3] >> 1) & 0x1F) as u16, 5);
        poly.coeffs[8 * i + 6] = decompress(((b[3] >> 6) | ((b[4] & 0x07) << 2)) as u16, 5);
        poly.coeffs[8 * i + 7] = decompress((b[4] >> 3) as u16, 5);
    }
    poly
}

// Compression with d=10 (320 bytes for 256 coefficients)
fn poly_compress_10(poly: &Poly, out: &mut [u8]) {
    for i in 0..64 {
        let mut t = [0u16; 4];
        for j in 0..4 {
            t[j] = compress(poly.coeffs[4 * i + j], 10);
        }
        // Pack 4 10-bit values into 5 bytes
        out[5 * i] = t[0] as u8;
        out[5 * i + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
        out[5 * i + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
        out[5 * i + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
        out[5 * i + 4] = (t[3] >> 2) as u8;
    }
}

fn poly_decompress_10(bytes: &[u8]) -> Poly {
    let mut poly = Poly::default();
    for i in 0..64 {
        let b = &bytes[5 * i..5 * i + 5];
        poly.coeffs[4 * i] = decompress((b[0] as u16) | ((b[1] as u16 & 0x03) << 8), 10);
        poly.coeffs[4 * i + 1] = decompress(((b[1] >> 2) as u16) | ((b[2] as u16 & 0x0F) << 6), 10);
        poly.coeffs[4 * i + 2] = decompress(((b[2] >> 4) as u16) | ((b[3] as u16 & 0x3F) << 4), 10);
        poly.coeffs[4 * i + 3] = decompress(((b[3] >> 6) as u16) | ((b[4] as u16) << 2), 10);
    }
    poly
}

// Compression with d=11 (352 bytes for 256 coefficients)
fn poly_compress_11(poly: &Poly, out: &mut [u8]) {
    for i in 0..32 {
        let mut t = [0u16; 8];
        for j in 0..8 {
            t[j] = compress(poly.coeffs[8 * i + j], 11);
        }
        // Pack 8 11-bit values into 11 bytes
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

fn poly_decompress_11(bytes: &[u8]) -> Poly {
    let mut poly = Poly::default();
    for i in 0..32 {
        let b = &bytes[11 * i..11 * i + 11];
        poly.coeffs[8 * i] = decompress((b[0] as u16) | ((b[1] as u16 & 0x07) << 8), 11);
        poly.coeffs[8 * i + 1] = decompress(((b[1] >> 3) as u16) | ((b[2] as u16 & 0x3F) << 5), 11);
        poly.coeffs[8 * i + 2] = decompress(
            ((b[2] >> 6) as u16) | ((b[3] as u16) << 2) | ((b[4] as u16 & 0x01) << 10),
            11,
        );
        poly.coeffs[8 * i + 3] = decompress(((b[4] >> 1) as u16) | ((b[5] as u16 & 0x0F) << 7), 11);
        poly.coeffs[8 * i + 4] = decompress(((b[5] >> 4) as u16) | ((b[6] as u16 & 0x7F) << 4), 11);
        poly.coeffs[8 * i + 5] = decompress(
            ((b[6] >> 7) as u16) | ((b[7] as u16) << 1) | ((b[8] as u16 & 0x03) << 9),
            11,
        );
        poly.coeffs[8 * i + 6] = decompress(((b[8] >> 2) as u16) | ((b[9] as u16 & 0x1F) << 6), 11);
        poly.coeffs[8 * i + 7] = decompress(((b[9] >> 5) as u16) | ((b[10] as u16) << 3), 11);
    }
    poly
}

// ============================================================================
// CBD Sampling (FIPS 203 Algorithm 8)
// ============================================================================

/// Sample a polynomial from the Centered Binomial Distribution.
///
/// Each coefficient is the difference of two sums of eta random bits.
/// Result is in range [-eta, eta].
///
/// # Arguments
/// * `eta` - CBD parameter (2 or 3)
/// * `bytes` - Random bytes (64*eta bytes required)
///
/// # Returns
/// Sampled polynomial
pub fn poly_cbd(eta: usize, bytes: &[u8]) -> Poly {
    let mut poly = Poly::default();
    match eta {
        2 => poly_cbd2(&mut poly, bytes),
        3 => poly_cbd3(&mut poly, bytes),
        _ => panic!("Unsupported eta value: {} (supported: 2, 3)", eta),
    }
    poly
}

/// CBD with eta=2: each coefficient uses 4 bits (2+2).
///
/// 256 coefficients * 4 bits = 1024 bits = 128 bytes required.
fn poly_cbd2(poly: &mut Poly, bytes: &[u8]) {
    for i in 0..128 {
        let t = bytes[i] as u32;

        // Count bits in each pair
        let d = (t & 0x55) + ((t >> 1) & 0x55);

        // First coefficient: bits 0-3
        let a = (d & 0x3) as i16;
        let b = ((d >> 2) & 0x3) as i16;
        poly.coeffs[2 * i] = a - b;

        // Second coefficient: bits 4-7
        let a = ((d >> 4) & 0x3) as i16;
        let b = ((d >> 6) & 0x3) as i16;
        poly.coeffs[2 * i + 1] = a - b;
    }
}

/// CBD with eta=3: each coefficient uses 6 bits (3+3).
///
/// 256 coefficients * 6 bits = 1536 bits = 192 bytes required.
fn poly_cbd3(poly: &mut Poly, bytes: &[u8]) {
    for i in 0..64 {
        // Read 3 bytes = 24 bits for 4 coefficients
        let t = (bytes[3 * i] as u32)
            | ((bytes[3 * i + 1] as u32) << 8)
            | ((bytes[3 * i + 2] as u32) << 16);

        // Count bits in each triple using magic constant 0x249249
        let d = (t & 0x249249) + ((t >> 1) & 0x249249) + ((t >> 2) & 0x249249);

        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            poly.coeffs[4 * i + j] = a - b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add() {
        let mut a = Poly::default();
        let mut b = Poly::default();

        for i in 0..N {
            a.coeffs[i] = i as i16;
            b.coeffs[i] = (N - i) as i16;
        }

        let c = poly_add(&a, &b);

        for i in 0..N {
            assert_eq!(c.coeffs[i], N as i16, "poly_add failed at index {}", i);
        }
    }

    #[test]
    fn test_poly_sub() {
        let mut a = Poly::default();
        let mut b = Poly::default();

        for i in 0..N {
            a.coeffs[i] = (2 * i) as i16;
            b.coeffs[i] = i as i16;
        }

        let c = poly_sub(&a, &b);

        for i in 0..N {
            assert_eq!(c.coeffs[i], i as i16, "poly_sub failed at index {}", i);
        }
    }

    #[test]
    fn test_compress_decompress_roundtrip_d4() {
        // Test values not too close to q (boundary causes wrap-around)
        for x in (0..(Q as i16 - 200)).step_by(100) {
            let compressed = compress(x, 4);
            let decompressed = decompress(compressed, 4);

            // Error should be at most ceil(q / 2^(d+1))
            let max_error = ((Q as i32) + (1 << 5) - 1) / (1 << 5);
            let error = ((x as i32) - (decompressed as i32)).abs();

            assert!(
                error <= max_error,
                "Compression error too large: d=4, x={}, compressed={}, decompressed={}, error={}, max={}",
                x, compressed, decompressed, error, max_error
            );
        }
    }

    #[test]
    fn test_compress_decompress_roundtrip_d10() {
        for x in (0..Q as i16).step_by(50) {
            let compressed = compress(x, 10);
            let decompressed = decompress(compressed, 10);

            let max_error = ((Q as i32) + (1 << 10)) / (1 << 11);
            let error = ((x as i32) - (decompressed as i32)).abs();

            assert!(
                error <= max_error,
                "Compression error too large: d=10, x={}, compressed={}, decompressed={}, error={}, max={}",
                x, compressed, decompressed, error, max_error
            );
        }
    }

    #[test]
    fn test_compress_range() {
        for d in [4u32, 5, 10, 11] {
            for x in (0..Q as i16).step_by(100) {
                let c = compress(x, d);
                assert!(
                    c < (1 << d),
                    "Compressed value {} out of range for d={}",
                    c,
                    d
                );
            }
        }
    }

    #[test]
    fn test_poly_compress_decompress_d4() {
        let mut poly = Poly::default();
        for i in 0..N {
            // Use values in middle range to avoid boundary issues
            poly.coeffs[i] = ((i * 13) % (Q as usize - 400)) as i16;
        }

        let mut compressed = [0u8; 128];
        poly_compress(&poly, 4, &mut compressed);
        let decompressed = poly_decompress(&compressed, 4);

        for i in 0..N {
            let max_error = ((Q as i32) + 31) / 32; // ceil(q/32)
            let error = ((poly.coeffs[i] as i32) - (decompressed.coeffs[i] as i32)).abs();
            assert!(
                error <= max_error,
                "Poly compression error at {}: original={}, decompressed={}, error={}",
                i,
                poly.coeffs[i],
                decompressed.coeffs[i],
                error
            );
        }
    }

    #[test]
    fn test_poly_compress_decompress_d10() {
        let mut poly = Poly::default();
        for i in 0..N {
            poly.coeffs[i] = ((i * 17) % Q as usize) as i16;
        }

        let mut compressed = [0u8; 320];
        poly_compress(&poly, 10, &mut compressed);
        let decompressed = poly_decompress(&compressed, 10);

        for i in 0..N {
            let max_error = ((Q as i32) + 1024) / 2048;
            let error = ((poly.coeffs[i] as i32) - (decompressed.coeffs[i] as i32)).abs();
            assert!(
                error <= max_error,
                "Poly compression error at {}: original={}, decompressed={}, error={}",
                i,
                poly.coeffs[i],
                decompressed.coeffs[i],
                error
            );
        }
    }

    #[test]
    fn test_cbd2_all_zeros() {
        let bytes = [0u8; 128];
        let poly = poly_cbd(2, &bytes);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], 0,
                "CBD2 with zero input should give zero polynomial"
            );
        }
    }

    #[test]
    fn test_cbd2_range() {
        // Test with various byte patterns
        let bytes: [u8; 128] = core::array::from_fn(|i| (i * 37) as u8);
        let poly = poly_cbd(2, &bytes);

        for (i, &c) in poly.coeffs.iter().enumerate() {
            assert!(
                c >= -2 && c <= 2,
                "CBD2 coefficient {} at index {} out of range [-2, 2]",
                c,
                i
            );
        }
    }

    #[test]
    fn test_cbd3_range() {
        let bytes: [u8; 192] = core::array::from_fn(|i| (i * 41) as u8);
        let poly = poly_cbd(3, &bytes);

        for (i, &c) in poly.coeffs.iter().enumerate() {
            assert!(
                c >= -3 && c <= 3,
                "CBD3 coefficient {} at index {} out of range [-3, 3]",
                c,
                i
            );
        }
    }

    #[test]
    fn test_cbd2_all_ones() {
        let bytes = [0xFFu8; 128];
        let poly = poly_cbd(2, &bytes);

        // With all bits = 1: each group of 2 bits sums to 2
        // So a = 2, b = 2, coefficient = 0
        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], 0,
                "CBD2 with all-ones should give zero at index {}",
                i
            );
        }
    }

    #[test]
    fn test_poly_basemul_commutativity() {
        use crate::ntt::ntt;
        use crate::reduce::to_mont;

        let mut a = Poly::default();
        let mut b = Poly::default();

        for i in 0..N {
            a.coeffs[i] = to_mont(((i * 17) % Q as usize) as i16);
            b.coeffs[i] = to_mont(((i * 31) % Q as usize) as i16);
        }

        ntt(&mut a);
        ntt(&mut b);

        let ab = poly_basemul(&a, &b);
        let ba = poly_basemul(&b, &a);

        for i in 0..N {
            assert_eq!(
                barrett_reduce_full(ab.coeffs[i]),
                barrett_reduce_full(ba.coeffs[i]),
                "Basemul not commutative at index {}",
                i
            );
        }
    }

    #[test]
    fn test_conditional_select() {
        let mut a = Poly::default();
        let mut b = Poly::default();

        for i in 0..N {
            a.coeffs[i] = 1;
            b.coeffs[i] = 2;
        }

        let selected_a = Poly::conditional_select(&a, &b, Choice::from(1u8));
        let selected_b = Poly::conditional_select(&a, &b, Choice::from(0u8));

        for i in 0..N {
            assert_eq!(selected_a.coeffs[i], 1);
            assert_eq!(selected_b.coeffs[i], 2);
        }
    }

    #[test]
    fn test_constant_time_eq() {
        let mut a = Poly::default();
        let mut b = Poly::default();

        for i in 0..N {
            a.coeffs[i] = i as i16;
            b.coeffs[i] = i as i16;
        }

        assert!(bool::from(a.ct_eq(&b)));

        b.coeffs[100] = 9999;
        assert!(!bool::from(a.ct_eq(&b)));
    }
}
