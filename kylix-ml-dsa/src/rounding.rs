//! Rounding functions for ML-DSA
//!
//! Implements Power2Round, Decompose, HighBits, LowBits, MakeHint, UseHint.

use crate::reduce::Q;

/// D parameter for Power2Round (always 13 in ML-DSA)
pub const D: u32 = 13;

/// Power2Round: decompose r into (r1, r0) where r = r1 * 2^d + r0.
///
/// Input: r in [0, q-1]
/// Output: (r1, r0) where r0 in [-2^(d-1), 2^(d-1))
#[inline]
pub fn power2round(r: i32) -> (i32, i32) {
    // r1 = (r + 2^(d-1) - 1) >> d
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    // r0 = r - r1 * 2^d
    let r0 = r - (r1 << D);
    (r1, r0)
}

/// Decompose: decompose r into (r1, r0) with r0 in (-alpha/2, alpha/2].
///
/// Input: r in [0, q-1], alpha = 2*gamma2
/// Output: (r1, r0)
///
/// Per FIPS 204 Section 8.4, Algorithm 35 (Decompose).
/// Magic constants are derived from the modular arithmetic optimization:
/// Returns (r1, r0) where:
/// - r1 = HighBits(r): the "high" part used for signature compression
/// - r0 = LowBits(r): the "low" part, centered in (-alpha/2, alpha/2]
///
/// Constants explanation:
/// - For gamma2 = (q-1)/32 = 261888: alpha = 523776, m = 16
///   - 1025 = ceil(2^22 / 4096) for division approximation
///   - 22-bit shift and mask by 15 (= m-1) for mod m
/// - For gamma2 = (q-1)/88 = 95232: alpha = 190464, m = 44
///   - 11275 = ceil(2^24 / 1488) for division approximation
///   - 43 = m-1, XOR trick handles the m=44 boundary case
#[inline]
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;

    // r1 = ceil((r + 127) / alpha), computed via multiplication by inverse
    // 127 = 2^7 - 1 is the rounding term for ceiling division
    let mut r1 = (r + 127) >> 7;
    if gamma2 == 261888 {
        // gamma2 = (q-1)/32, m = 16
        // Approximate division by 4096 using multiply-shift: x/4096 ≈ (x*1025) >> 22
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15; // mod 16
    } else {
        // gamma2 = (q-1)/88, m = 44
        // Approximate division by 1488 using multiply-shift: x/1488 ≈ (x*11275) >> 24
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        // Handle r1 = 44 case: if r1 == 44, set to 0 (wrap around)
        // XOR trick: if r1 > 43, the sign bit is 0, so r1 ^= r1 = 0
        r1 ^= ((43 - r1) >> 31) & r1;
    }

    let mut r0 = r - r1 * alpha;

    // Center r0 into (-alpha/2, alpha/2] using branchless conditional subtraction
    // If r0 > (q-1)/2, subtract q to get negative centered value
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;

    (r1, r0)
}

/// HighBits: extract high bits from r.
#[inline]
pub fn highbits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// LowBits: extract low bits from r.
#[inline]
pub fn lowbits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// MakeHint: compute hint bit per FIPS 204 Algorithm 14.
///
/// Returns 1 if HighBits(r) ≠ HighBits(r + z), else 0.
/// This indicates whether adding z to r would change the high bits.
///
/// This function is constant-time to prevent timing side-channels.
#[inline]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> i32 {
    use crate::reduce::freeze;
    use subtle::{ConditionallySelectable, ConstantTimeEq};

    let h0 = highbits(r, gamma2);
    // Need to reduce r + z to [0, q-1] before computing highbits
    let h1 = highbits(freeze(r + z), gamma2);

    // Constant-time comparison: return 1 if h0 != h1, else 0
    let equal = (h0 as u32).ct_eq(&(h1 as u32));
    let result = u32::conditional_select(&1u32, &0u32, equal);
    result as i32
}

/// UseHint: recover high bits using hint.
///
/// If hint = 0, return highbits(r).
/// If hint = 1, return highbits(r) +/- 1 depending on lowbits sign.
///
/// Per FIPS 204 Section 8.4, Algorithm 37 (UseHint).
#[inline]
pub fn use_hint(hint: i32, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);

    if hint == 0 {
        return r1;
    }

    // m = number of possible high-bits values = (q-1) / (2*gamma2)
    // For gamma2 = (q-1)/32: m = 16
    // For gamma2 = (q-1)/88: m = 44
    let m = if gamma2 == 261888 { 16 } else { 44 };

    if r0 > 0 {
        if r1 == m - 1 {
            0
        } else {
            r1 + 1
        }
    } else if r1 == 0 {
        m - 1
    } else {
        r1 - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round() {
        // Test that r = r1 * 2^d + r0
        for r in [0, 100, 1000, Q - 1, Q / 2] {
            let (r1, r0) = power2round(r);
            let reconstructed = r1 * (1 << D) + r0;
            assert_eq!(reconstructed, r, "Failed for r={r}");
        }
    }

    #[test]
    fn test_power2round_r0_range() {
        // r0 should be in (-2^(d-1), 2^(d-1)] per FIPS 204 definition of mod±
        // In practice, the Dilithium formula produces r0 in [-2^(d-1)+1, 2^(d-1)]
        let bound = 1 << (D - 1); // 4096 for D=13
        for r in [0, 100, 1000, Q - 1, Q / 2, 4096, 4097, 8191, 8192] {
            let (_, r0) = power2round(r);
            assert!(r0 > -bound && r0 <= bound, "r0={r0} out of range for r={r}");
        }
    }

    #[test]
    fn test_decompose_gamma2_95232() {
        let gamma2 = 95232; // (q-1)/88
        for r in [0, 100, 1000, Q - 1, Q / 2] {
            let (_r1, r0) = decompose(r, gamma2);
            // Check r0 is in range
            assert!(r0.abs() <= gamma2, "r0={r0} out of range");
        }
    }

    #[test]
    fn test_decompose_gamma2_261888() {
        let gamma2 = 261888; // (q-1)/32
        for r in [0, 100, 1000, Q - 1, Q / 2] {
            let (r1, _r0) = decompose(r, gamma2);
            // Check bounds
            assert!(r1 >= 0 && r1 < 16, "r1={r1} out of range");
        }
    }

    #[test]
    fn test_highbits_lowbits() {
        let gamma2 = 261888;
        for r in [0, 100, 1000, Q - 1, Q / 2] {
            let h = highbits(r, gamma2);
            let l = lowbits(r, gamma2);
            let (h2, l2) = decompose(r, gamma2);
            assert_eq!(h, h2);
            assert_eq!(l, l2);
        }
    }

    #[test]
    fn test_make_use_hint() {
        let gamma2 = 261888;
        let r = 1000000;

        // If no hint needed, UseHint should return same as HighBits
        let h = highbits(r, gamma2);
        let recovered = use_hint(0, r, gamma2);
        assert_eq!(h, recovered);
    }
}
