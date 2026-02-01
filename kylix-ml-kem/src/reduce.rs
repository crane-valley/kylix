//! Modular arithmetic operations for ML-KEM.
//!
//! This module provides constant-time Barrett and Montgomery reduction
//! for efficient modular arithmetic in the polynomial ring Z_q\[X\]/(X^256 + 1).
//!
//! This module uses macros from kylix-core to generate the reduction functions.

// Reduction functions include both Barrett and Montgomery; not all always used.
#![allow(dead_code)]

use crate::params::common::Q;
use kylix_core::{define_barrett_reduce_rounded, define_montgomery_mul, define_montgomery_reduce};

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

// Generate Barrett reduction with rounding
define_barrett_reduce_rounded! {
    name: barrett_reduce,
    coeff: i16,
    wide: i32,
    q: Q,
    barrett_mul: BARRETT_MUL,
    shift: 26
}

// Generate Montgomery reduction
define_montgomery_reduce! {
    name: montgomery_reduce,
    coeff: i16,
    wide: i32,
    q: Q,
    qinv: QINV,
    shift: 16
}

// Generate Montgomery multiplication
define_montgomery_mul! {
    name: montgomery_mul,
    coeff: i16,
    wide: i32,
    montgomery_reduce: montgomery_reduce
}

/// Conditional reduce: subtract q if r >= q
///
/// This ensures the result is in canonical form [0, q-1].
#[inline]
pub const fn cond_reduce(r: i16) -> i16 {
    let diff = r - Q as i16;
    // If diff >= 0, use diff; otherwise use r
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
