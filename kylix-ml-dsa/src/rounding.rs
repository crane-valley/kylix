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
#[inline]
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let alpha = 2 * gamma2;

    // r1 = ceil((r + 127) / alpha)
    let mut r1 = (r + 127) >> 7;
    if gamma2 == 261888 {
        // gamma2 = (q-1)/32
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15;
    } else {
        // gamma2 = (q-1)/88
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
    }

    let mut r0 = r - r1 * alpha;

    // Center r0
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
#[inline]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> i32 {
    use crate::reduce::freeze;

    let h0 = highbits(r, gamma2);
    // Need to reduce r + z to [0, q-1] before computing highbits
    let h1 = highbits(freeze(r + z), gamma2);
    if h0 != h1 {
        1
    } else {
        0
    }
}

/// UseHint: recover high bits using hint.
///
/// If hint = 0, return highbits(r).
/// If hint = 1, return highbits(r) +/- 1 depending on lowbits sign.
#[inline]
pub fn use_hint(hint: i32, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);

    if hint == 0 {
        return r1;
    }

    let _alpha = 2 * gamma2; // Computed for reference but not used in this implementation
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
            assert!(
                r0 > -bound && r0 <= bound,
                "r0={r0} out of range for r={r}"
            );
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
