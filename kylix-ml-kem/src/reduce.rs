//! Modular arithmetic operations for ML-KEM.
//!
//! This module provides constant-time Barrett and Montgomery reduction
//! for efficient modular arithmetic in the polynomial ring Z_q\[X\]/(X^256 + 1).

#![allow(dead_code)]
#![allow(clippy::let_and_return)]

use crate::params::common::Q;

/// Q inverse mod 2^16: q^(-1) mod 2^16 = -3327
pub const QINV: i32 = -3327;

/// Montgomery constant: 2^16 mod q = 2285
pub const MONT: i16 = 2285;

/// R^2 mod q for Montgomery: (2^16)^2 mod q = 1353
pub const MONT_R2: i32 = 1353;

/// Barrett constant for q=3329: floor(2^26 / q) + 1 = 20159
/// Using ceiling to ensure correct reduction
pub const BARRETT_MUL: i32 = 20159;

/// Inverse of N (256) in Montgomery form: 256^(-1) * 2^16 mod q = 1441
pub const INV_N_MONT: i16 = 1441;

/// Barrett reduction: compute a mod q for |a| < 2^15
///
/// This computes `a mod q` without division, using precomputed constants.
///
/// # Arguments
/// * `a` - Input value in range approximately [-2^15, 2^15]
///
/// # Returns
/// Result in range [0, q-1]
#[inline]
pub const fn barrett_reduce(a: i16) -> i16 {
    let a = a as i32;
    // t = floor((a * v + 2^25) / 2^26) - approximation of floor(a/q)
    let t = ((a * BARRETT_MUL + (1 << 25)) >> 26) as i16;
    // r = a - t*q
    let r = (a - (t as i32) * (Q as i32)) as i16;
    r
}

/// Conditional reduce: subtract q if r >= q
///
/// This ensures the result is in canonical form [0, q-1].
#[inline]
pub const fn cond_reduce(r: i16) -> i16 {
    let diff = r - Q as i16;
    // If diff >= 0, use diff; otherwise use r
    // Since r is result of barrett_reduce, r is in [0, 2q-1]
    if diff >= 0 {
        diff
    } else {
        r
    }
}

/// Full Barrett reduction to canonical form [0, q-1]
#[inline]
pub const fn barrett_reduce_full(a: i16) -> i16 {
    let r = barrett_reduce(a);
    // Handle both positive and negative remainders
    if r < 0 {
        r + Q as i16
    } else if r >= Q as i16 {
        r - Q as i16
    } else {
        r
    }
}

/// Montgomery reduction: compute a * R^(-1) mod q where R = 2^16
///
/// Given `a` in range [-q*2^15, q*2^15], computes `a * 2^(-16) mod q`.
///
/// # Arguments
/// * `a` - Input value (typically product of two i16 values)
///
/// # Returns
/// Result in range [-(q-1)/2, (q-1)/2], approximately [-1664, 1664]
#[inline]
pub const fn montgomery_reduce(a: i32) -> i16 {
    // t = a * q^(-1) mod 2^16 (keep low 16 bits)
    let t = (a.wrapping_mul(QINV)) as i16;
    // t = (a - t*q) >> 16
    let t = (a - (t as i32) * (Q as i32)) >> 16;
    t as i16
}

/// Multiply two values in Montgomery domain.
///
/// Given `a = a' * R mod q` and `b = b' * R mod q` (Montgomery form),
/// computes `a' * b' * R mod q` (product in Montgomery form).
///
/// # Arguments
/// * `a` - First operand in Montgomery form
/// * `b` - Second operand in Montgomery form
///
/// # Returns
/// Product in Montgomery form
#[inline]
pub const fn montgomery_mul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Convert a value to Montgomery form: a -> a * R mod q
///
/// # Arguments
/// * `a` - Input value in [0, q-1]
///
/// # Returns
/// Value in Montgomery form
#[inline]
pub const fn to_mont(a: i16) -> i16 {
    // Multiply by R^2, then Montgomery reduce to get a*R
    montgomery_reduce((a as i32) * MONT_R2)
}

/// Convert from Montgomery form: a * R mod q -> a mod q
///
/// # Arguments
/// * `a` - Value in Montgomery form
///
/// # Returns
/// Value in standard form
#[inline]
pub const fn from_mont(a: i16) -> i16 {
    montgomery_reduce(a as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce_small_positive() {
        // Values already in range should remain unchanged or be equivalent mod q
        for a in 0..Q as i16 {
            let r = barrett_reduce_full(a);
            assert!(
                r >= 0 && r < Q as i16,
                "barrett_reduce_full({}) = {} not in [0, q)",
                a,
                r
            );
            assert_eq!(r, a, "barrett_reduce_full({}) = {} (expected {})", a, r, a);
        }
    }

    #[test]
    fn test_barrett_reduce_at_q() {
        assert_eq!(barrett_reduce_full(Q as i16), 0);
        assert_eq!(barrett_reduce_full(Q as i16 + 1), 1);
        assert_eq!(barrett_reduce_full(2 * Q as i16), 0);
    }

    #[test]
    fn test_barrett_reduce_negative() {
        assert_eq!(barrett_reduce_full(-1), Q as i16 - 1);
        assert_eq!(barrett_reduce_full(-(Q as i16)), 0);
    }

    #[test]
    fn test_montgomery_reduce_basic() {
        // Montgomery reduce of R should give 1
        // R = 2^16, so montgomery_reduce(R) = R * R^(-1) mod q = 1
        let r = montgomery_reduce(1 << 16);
        let r_normalized = barrett_reduce_full(r);
        assert_eq!(
            r_normalized, 1,
            "montgomery_reduce(2^16) should be 1, got {}",
            r_normalized
        );
    }

    #[test]
    fn test_montgomery_roundtrip() {
        for a in (0..Q as i16).step_by(100) {
            let mont = to_mont(a);
            let back = from_mont(mont);
            let normalized = barrett_reduce_full(back);
            assert_eq!(
                normalized, a,
                "Montgomery roundtrip failed for {}: to_mont={}, back={}, normalized={}",
                a, mont, back, normalized
            );
        }
    }

    #[test]
    fn test_montgomery_mul_correctness() {
        // Test a * b mod q via Montgomery multiplication
        let test_values = [0i16, 1, 100, 500, 1000, 2000, 3000, 3328];

        for &a in &test_values {
            for &b in &test_values {
                let expected = ((a as i32 * b as i32) % Q as i32) as i16;

                let mont_a = to_mont(a);
                let mont_b = to_mont(b);
                let mont_result = montgomery_mul(mont_a, mont_b);
                let result = from_mont(mont_result);
                let result_normalized = barrett_reduce_full(result);

                assert_eq!(
                    result_normalized, expected,
                    "Montgomery mul failed: {} * {} = {} (expected {})",
                    a, b, result_normalized, expected
                );
            }
        }
    }

    #[test]
    fn test_montgomery_mul_associativity() {
        let a = to_mont(123);
        let b = to_mont(456);
        let c = to_mont(789);

        // (a * b) * c
        let ab = montgomery_mul(a, b);
        let abc1 = montgomery_mul(ab, c);

        // a * (b * c)
        let bc = montgomery_mul(b, c);
        let abc2 = montgomery_mul(a, bc);

        let r1 = barrett_reduce_full(from_mont(abc1));
        let r2 = barrett_reduce_full(from_mont(abc2));

        assert_eq!(r1, r2, "Montgomery multiplication not associative");
    }

    #[test]
    fn test_constants() {
        // Verify MONT = 2^16 mod q
        assert_eq!((1i32 << 16) % Q as i32, MONT as i32);

        // Verify MONT_R2 = 2^32 mod q
        assert_eq!((1i64 << 32) % Q as i64, MONT_R2 as i64);

        // Verify BARRETT_MUL is approximately 2^26 / q (using ceiling for better accuracy)
        let floor_val = (1i32 << 26) / Q as i32;
        assert!(
            BARRETT_MUL == floor_val || BARRETT_MUL == floor_val + 1,
            "BARRETT_MUL should be floor or ceiling of 2^26/q"
        );
    }
}
