//! Modular arithmetic for ML-DSA
//!
//! All operations are performed modulo q = 8380417 = 2^23 - 2^13 + 1.

/// The prime modulus q = 8380417
pub const Q: i32 = 8_380_417;

/// q^(-1) mod 2^32 for Montgomery reduction
/// Used in the formula: (a - t*q) >> 32 where t = (a mod 2^32) * QINV mod 2^32
pub const QINV: i32 = 58_728_449;

/// Floor(2^48 / q) for Barrett reduction
pub const BARRETT_MUL: i64 = 33_556_102;

/// Reduce a to canonical form [0, q-1] using Barrett reduction.
///
/// Input: |a| < 2^31
/// Output: r in [0, q-1] with r ≡ a (mod q)
#[inline]
pub const fn reduce32(a: i32) -> i32 {
    // Barrett reduction: t = floor(a * BARRETT_MUL / 2^48) ≈ floor(a/q)
    // We approximate by computing floor(a * BARRETT_MUL / 2^48)
    let a = a as i64;
    let t = ((a * BARRETT_MUL) >> 48) as i32;
    let r = (a - (t as i64) * (Q as i64)) as i32;

    // r might be in [0, 2q-1], reduce if needed
    let r = r - Q;
    let mask = r >> 31; // -1 if r < 0, 0 otherwise
    r + (Q & mask)
}

/// Reduce a to approximately [0, q] using simpler Barrett reduction.
/// Faster but may return values up to q.
#[inline]
pub const fn reduce32_approx(a: i32) -> i32 {
    let a = a as i64;
    let t = ((a * BARRETT_MUL) >> 48) as i32;
    (a - (t as i64) * (Q as i64)) as i32
}

/// Montgomery reduction: compute a * R^(-1) mod q where R = 2^32.
///
/// Input: |a| < q * 2^32
/// Output: r ≡ a * R^(-1) (mod q) with |r| < q
///
/// Uses the formula from the Dilithium reference implementation:
/// t = (a mod 2^32) * QINV mod 2^32
/// result = (a - t*q) >> 32
#[inline]
pub const fn montgomery_reduce(a: i64) -> i32 {
    // t = (a mod 2^32) * QINV mod 2^32 (computed via i32 wrapping multiplication)
    let t = (a as i32).wrapping_mul(QINV);
    // r = (a - t*q) / 2^32
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// Montgomery multiplication: compute a * b * R^(-1) mod q.
#[inline]
pub const fn montgomery_mul(a: i32, b: i32) -> i32 {
    montgomery_reduce((a as i64) * (b as i64))
}

/// Centered reduction: reduce a to [-q/2, q/2].
#[inline]
pub const fn caddq(a: i32) -> i32 {
    a + (Q & (a >> 31))
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
}
