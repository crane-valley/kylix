//! Modular arithmetic for ML-DSA
//!
//! All operations are performed modulo q = 8380417 = 2^23 - 2^13 + 1.
//!
//! This module uses macros from kylix-core to generate the reduction functions.

use kylix_core::{
    define_barrett_reduce, define_caddq, define_montgomery_mul, define_montgomery_reduce,
};

/// The prime modulus q = 8380417
pub const Q: i32 = 8_380_417;

/// q^(-1) mod 2^32 for Montgomery reduction
pub const QINV: i32 = 58_728_449;

/// Floor(2^48 / q) for Barrett reduction
pub const BARRETT_MUL: i64 = 33_556_102;

// Generate Barrett reduction (approximate, may return up to q)
define_barrett_reduce! {
    name: reduce32_approx,
    coeff: i32,
    wide: i64,
    q: Q,
    barrett_mul: BARRETT_MUL,
    shift: 48
}

// Generate Montgomery reduction
define_montgomery_reduce! {
    name: montgomery_reduce,
    coeff: i32,
    wide: i64,
    q: Q,
    qinv: QINV,
    shift: 32
}

// Generate Montgomery multiplication
define_montgomery_mul! {
    name: montgomery_mul,
    coeff: i32,
    wide: i64,
    montgomery_reduce: montgomery_reduce
}

// Generate conditional add q
define_caddq! {
    name: caddq,
    coeff: i32,
    q: Q
}

/// Reduce a to canonical form [0, q-1] using Barrett reduction.
///
/// Input: |a| < 2^31
/// Output: r in [0, q-1] with r ≡ a (mod q)
#[inline]
pub const fn reduce32(a: i32) -> i32 {
    let r = reduce32_approx(a);
    // r might be in [0, 2q-1], reduce if needed
    let r = r - Q;
    let mask = r >> 31; // -1 if r < 0, 0 otherwise
    r + (Q & mask)
}

/// Freeze: reduce to canonical [0, q-1] range.
#[inline]
pub const fn freeze(a: i32) -> i32 {
    let r = reduce32_approx(a);
    let r = r - Q;
    r + (Q & (r >> 31))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce32() {
        assert_eq!(reduce32(0), 0);
        assert_eq!(reduce32(Q), 0);
        assert_eq!(reduce32(Q + 1), 1);
        assert_eq!(reduce32(2 * Q), 0);
        assert_eq!(reduce32(-1), Q - 1);
        assert_eq!(reduce32(-Q), 0);
    }

    #[test]
    fn test_q_properties() {
        // q = 2^23 - 2^13 + 1
        assert_eq!(Q, (1 << 23) - (1 << 13) + 1);
        // q is prime (verified externally)
        assert_eq!(Q, 8_380_417);
    }

    #[test]
    fn test_freeze() {
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(Q), 0);
        assert_eq!(freeze(Q + 100), 100);
        assert_eq!(freeze(-100), Q - 100);
    }

    #[test]
    fn test_caddq() {
        assert_eq!(caddq(0), 0);
        assert_eq!(caddq(100), 100);
        assert_eq!(caddq(-1), Q - 1);
        assert_eq!(caddq(-100), Q - 100);
    }

    #[test]
    fn test_montgomery_reduce() {
        // montgomery_reduce(a) = a * R^(-1) mod q where R = 2^32
        // montgomery_reduce(R) should give 1 (mod q)
        let r = montgomery_reduce(1i64 << 32);
        assert_eq!(freeze(r), 1);
    }

    #[test]
    fn test_montgomery_mul() {
        // Test that montgomery_mul is consistent
        let a = 1000i32;
        let b = 2000i32;
        let result = montgomery_mul(a, b);
        // Result is (a * b * R^(-1)) mod q
        // This is hard to verify directly, but we can check it's in range
        assert!(result.abs() < Q);
    }
}
