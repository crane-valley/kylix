//! Modular arithmetic for ML-DSA
//!
//! All operations are performed modulo q = 8380417 = 2^23 - 2^13 + 1.
//!
//! This module uses macros from kylix-core to generate the reduction functions.

use kylix_core::{
    define_barrett_reduce, define_caddq, define_freeze, define_montgomery_mul,
    define_montgomery_reduce,
};

/// The prime modulus q = 8380417
pub const Q: i32 = 8_380_417;

/// q^(-1) mod 2^32 used in the Montgomery reduction step
///     (a - t * q) >> 32
/// where t = (a mod 2^32) * QINV mod 2^32.
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

// Generate reduce32: canonical reduction to [0, q-1]
define_freeze! {
    name: reduce32,
    coeff: i32,
    q: Q,
    reduce_approx: reduce32_approx
}

/// Freeze: reduce to canonical [0, q-1] range.
///
/// This is a thin wrapper around [`reduce32`] kept for API compatibility
/// and to match the terminology used in the ML-DSA specification.
#[inline]
pub const fn freeze(a: i32) -> i32 {
    reduce32(a)
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

        // montgomery_reduce(0) should give 0
        assert_eq!(freeze(montgomery_reduce(0i64)), 0);

        // montgomery_reduce(q * R) should give 0 (mod q)
        assert_eq!(freeze(montgomery_reduce((Q as i64) << 32)), 0);

        // montgomery_reduce(-R) should give q - 1 (mod q)
        assert_eq!(freeze(montgomery_reduce(-(1i64 << 32))), Q - 1);

        // montgomery_reduce(2R) should give 2 (mod q)
        assert_eq!(freeze(montgomery_reduce(2i64 << 32)), 2);
    }

    #[test]
    fn test_montgomery_mul() {
        // Verify round-trip: montgomery_mul(a, R^2) = a * R (mod q),
        // so freeze(montgomery_reduce(montgomery_mul(a, R^2_mod_q_in_mont))) recovers a.
        // Simpler: verify that montgomery_mul(R mod q, R mod q) = R^2 * R^(-1) = R (mod q)
        let mont_r_mod_q = ((1i64 << 32) % Q as i64) as i32; // R mod q
        let result = montgomery_mul(mont_r_mod_q, mont_r_mod_q);
        // result = R * R * R^(-1) mod q = R mod q
        assert_eq!(freeze(result), mont_r_mod_q);

        // montgomery_mul(0, x) should give 0
        assert_eq!(freeze(montgomery_mul(0, 1000)), 0);

        // montgomery_mul(a, 1) = a * R^(-1) mod q
        // So freeze(montgomery_mul(R mod q, 1)) = R^(-1) * R mod q = 1
        // Actually: montgomery_mul(R mod q, 1) = (R mod q) * 1 * R^(-1) = 1
        assert_eq!(freeze(montgomery_mul(mont_r_mod_q, 1)), 1);
    }
}
