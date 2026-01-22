//! Number Theoretic Transform (NTT) for ML-KEM.
//!
//! This module implements the forward and inverse NTT as specified in FIPS 203.
//! The NTT is used to efficiently multiply polynomials in the ring Z_q\[X\]/(X^256 + 1).
//!
//! All operations are constant-time.

#![allow(dead_code)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::manual_range_contains)]

use crate::poly::Poly;
use crate::reduce::{barrett_reduce, montgomery_mul, INV_N_MONT};

/// Precomputed zetas (twiddle factors) in Montgomery form.
///
/// These are the powers of the primitive 256th root of unity (zeta = 17)
/// in bit-reversed order, multiplied by R = 2^16 mod q.
///
/// zetas[i] = zeta^(brv(i)) * R mod q, where brv is 7-bit bit-reversal.
pub const ZETAS: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

/// Forward NTT: Transform polynomial from coefficient representation
/// to NTT domain (evaluations at 256th roots of unity).
///
/// Uses Cooley-Tukey butterfly with decimation-in-time.
/// After NTT, coefficients are in Montgomery form.
///
/// # Arguments
/// * `poly` - Polynomial to transform (modified in-place)
///
/// # Algorithm
/// This implements the NTT as specified in FIPS 203 Algorithm 9.
pub fn ntt(poly: &mut Poly) {
    let mut k: usize = 1;
    let mut len: usize = 128;

    while len >= 2 {
        let mut start: usize = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;

            for j in start..(start + len) {
                // Cooley-Tukey butterfly
                let t = montgomery_mul(zeta, poly.coeffs[j + len]);
                poly.coeffs[j + len] = poly.coeffs[j] - t;
                poly.coeffs[j] = poly.coeffs[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT: Transform from NTT domain back to coefficient representation.
///
/// Uses Gentleman-Sande butterfly with decimation-in-frequency.
/// Output is multiplied by n^(-1) which is folded into the computation.
///
/// # Arguments
/// * `poly` - Polynomial in NTT domain to transform (modified in-place)
///
/// # Algorithm
/// This implements the inverse NTT as specified in FIPS 203 Algorithm 10.
pub fn inv_ntt(poly: &mut Poly) {
    let mut k: usize = 127;
    let mut len: usize = 2;

    while len <= 128 {
        let mut start: usize = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                // Gentleman-Sande butterfly
                let t = poly.coeffs[j];
                // Use Barrett reduction on the sum to keep values bounded
                poly.coeffs[j] = barrett_reduce(t.wrapping_add(poly.coeffs[j + len]));
                // Note: use t - poly[j+len] (not the other way) and negate for inverse
                poly.coeffs[j + len] = montgomery_mul(-zeta, t.wrapping_sub(poly.coeffs[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by n^(-1) = 128^(-1) mod q in Montgomery form
    for i in 0..256 {
        poly.coeffs[i] = montgomery_mul(INV_N_MONT, poly.coeffs[i]);
    }
}

/// Base multiplication for a single pair of coefficients in NTT domain.
///
/// Computes (a0 + a1*X)(b0 + b1*X) mod (X^2 - zeta), which gives:
/// result = (a0*b0 + a1*b1*zeta) + (a0*b1 + a1*b0)*X
///
/// # Arguments
/// * `r` - Output slice of length 2
/// * `a` - First input slice of length 2
/// * `b` - Second input slice of length 2
/// * `zeta` - The twiddle factor for this pair
#[inline]
pub fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    // r[0] = a[0]*b[0] + a[1]*b[1]*zeta
    let t = montgomery_mul(a[1], b[1]);
    r[0] = montgomery_mul(t, zeta);
    r[0] = r[0] + montgomery_mul(a[0], b[0]);

    // r[1] = a[0]*b[1] + a[1]*b[0]
    r[1] = montgomery_mul(a[0], b[1]);
    r[1] = r[1] + montgomery_mul(a[1], b[0]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reduce::barrett_reduce_full;

    #[test]
    fn test_ntt_inv_ntt_roundtrip() {
        // NTT followed by INVNTT returns original * R (Montgomery form)
        // This is the expected behavior - need from_mont to get back to normal form
        let mut poly = Poly::default();
        for i in 0..256 {
            poly.coeffs[i] = (i as i16) % 3329;
        }

        // Store original
        let mut original = Poly::default();
        for i in 0..256 {
            original.coeffs[i] = poly.coeffs[i];
        }

        // Forward then inverse
        ntt(&mut poly);
        inv_ntt(&mut poly);

        // Result is in Montgomery form - need from_mont to convert back
        for i in 0..256 {
            let reduced = barrett_reduce_full(crate::reduce::from_mont(poly.coeffs[i]));
            let orig = barrett_reduce_full(original.coeffs[i]);
            assert_eq!(
                reduced, orig,
                "NTT roundtrip failed at index {}: got {}, expected {}",
                i, reduced, orig
            );
        }
    }

    #[test]
    fn test_ntt_zero_polynomial() {
        let mut poly = Poly::default();
        ntt(&mut poly);

        for i in 0..256 {
            assert_eq!(
                poly.coeffs[i], 0,
                "NTT of zero polynomial should be zero at index {}",
                i
            );
        }
    }

    #[test]
    fn test_ntt_inv_ntt_roundtrip_random_like() {
        // Use a deterministic "random-like" pattern
        let mut poly = Poly::default();
        for i in 0..256 {
            poly.coeffs[i] = ((i * 17 + 31) % 3329) as i16;
        }

        let mut original = Poly::default();
        for i in 0..256 {
            original.coeffs[i] = poly.coeffs[i];
        }

        ntt(&mut poly);
        inv_ntt(&mut poly);

        // Result is in Montgomery form - need from_mont to convert back
        for i in 0..256 {
            let reduced = barrett_reduce_full(crate::reduce::from_mont(poly.coeffs[i]));
            let orig = barrett_reduce_full(original.coeffs[i]);
            assert_eq!(reduced, orig, "NTT roundtrip failed at index {}", i);
        }
    }

    #[test]
    fn test_zetas_in_valid_range() {
        for (i, &z) in ZETAS.iter().enumerate() {
            assert!(
                z >= 0 && z < 3329,
                "ZETAS[{}] = {} out of range [0, 3329)",
                i,
                z
            );
        }
    }

    #[test]
    fn test_zetas_first_value() {
        // zetas[0] should be 1 * R mod q = MONT = 2285
        assert_eq!(ZETAS[0], 2285, "ZETAS[0] should be MONT (2285)");
    }

    #[test]
    fn test_basemul_basic() {
        // Test (1 + 0*X) * (1 + 0*X) = 1
        let a = [2285i16, 0]; // 1 in Montgomery form
        let b = [2285i16, 0]; // 1 in Montgomery form
        let zeta = ZETAS[64]; // Some zeta value
        let mut r = [0i16; 2];

        basemul(&mut r, &a, &b, zeta);

        // Result should be 1 in Montgomery form
        let r0 = barrett_reduce_full(crate::reduce::from_mont(r[0]));
        let r1 = barrett_reduce_full(crate::reduce::from_mont(r[1]));

        assert_eq!(r0, 1, "basemul(1, 1) constant term should be 1, got {}", r0);
        assert_eq!(r1, 0, "basemul(1, 1) linear term should be 0, got {}", r1);
    }

    #[test]
    fn test_ntt_modifies_polynomial() {
        let mut poly = Poly::default();
        for i in 0..256 {
            poly.coeffs[i] = 1; // All ones
        }

        let _original_sum: i32 = poly.coeffs.iter().map(|&x| x as i32).sum();

        ntt(&mut poly);

        // After NTT, the polynomial should be different (except for the DC component)
        let _ntt_sum: i32 = poly.coeffs.iter().map(|&x| x as i32).sum();

        // The values should have changed
        let mut same_count = 0;
        for i in 0..256 {
            if poly.coeffs[i] == 1 {
                same_count += 1;
            }
        }
        // Not all coefficients should remain 1 after NTT
        assert!(same_count < 256, "NTT should modify coefficients");
    }
}
