//! Polynomial arithmetic for ML-DSA
//!
//! Polynomials are elements of the ring R_q = Z_q[X] / (X^256 + 1)
//! where q = 8380417.

use crate::ntt::{inv_ntt, ntt};
use crate::reduce::{caddq, freeze, montgomery_mul, reduce32, Q};
use zeroize::Zeroize;

/// Ring dimension N = 256
pub const N: usize = 256;

/// A polynomial in R_q with 256 coefficients.
#[derive(Clone, Zeroize)]
pub struct Poly {
    /// Coefficients in Z_q
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// Create a zero polynomial.
    #[inline]
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create a polynomial from coefficients.
    #[inline]
    pub const fn new(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Reduce all coefficients to [0, q-1].
    pub fn reduce(&mut self) {
        #[cfg(feature = "simd")]
        if crate::simd::reduce(&mut self.coeffs) {
            return;
        }
        for c in &mut self.coeffs {
            *c = reduce32(*c);
        }
    }

    /// Reduce all coefficients with conditional add.
    pub fn caddq(&mut self) {
        #[cfg(feature = "simd")]
        if crate::simd::caddq(&mut self.coeffs) {
            return;
        }
        for c in &mut self.coeffs {
            *c = caddq(*c);
        }
    }

    /// Freeze coefficients to canonical [0, q-1] form.
    pub fn freeze(&mut self) {
        for c in &mut self.coeffs {
            *c = freeze(*c);
        }
    }

    /// Forward NTT transform (in place).
    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    /// Inverse NTT transform (in place).
    pub fn inv_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    /// Add two polynomials: r = a + b.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        r
    }

    /// Add another polynomial in place: self += other.
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] += other.coeffs[i];
        }
    }

    /// Subtract two polynomials: r = a - b.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        r
    }

    /// Subtract another polynomial in place: self -= other.
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] -= other.coeffs[i];
        }
    }

    /// Pointwise multiplication in NTT domain: r = a * b.
    /// Both inputs must be in NTT form.
    #[must_use]
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut r = Self::zero();

        // Try SIMD optimized path (safe wrapper handles unsafe internally)
        #[cfg(feature = "simd")]
        {
            if crate::simd::pointwise_mul(&mut r.coeffs, &self.coeffs, &other.coeffs) {
                return r;
            }
        }

        // Scalar fallback
        for i in 0..N {
            r.coeffs[i] = montgomery_mul(self.coeffs[i], other.coeffs[i]);
        }
        r
    }

    /// Pointwise multiply and accumulate: self += a * b (in NTT domain).
    pub fn pointwise_mul_acc(&mut self, a: &Self, b: &Self) {
        // Try SIMD optimized path (safe wrapper handles unsafe internally)
        #[cfg(feature = "simd")]
        {
            if crate::simd::pointwise_mul_acc(&mut self.coeffs, &a.coeffs, &b.coeffs) {
                return;
            }
        }

        // Scalar fallback
        for i in 0..N {
            self.coeffs[i] += montgomery_mul(a.coeffs[i], b.coeffs[i]);
        }
    }

    /// Shift coefficients left by d bits: self = self << d.
    pub fn shift_left(&mut self, d: u32) {
        for c in &mut self.coeffs {
            *c <<= d;
        }
    }

    /// Check if infinity norm is less than bound.
    /// Returns true if all |coeffs[i]| < bound.
    ///
    /// This function is constant-time to prevent timing side-channels
    /// when checking secret-dependent polynomials.
    ///
    /// Handles both reduced coefficients in [0, Q-1] and centered
    /// coefficients that may be negative.
    pub fn check_norm(&self, bound: i32) -> bool {
        bool::from(self.check_norm_ct(bound))
    }

    /// Check infinity norm of all coefficients (constant-time, returns Choice).
    ///
    /// Returns `Choice(1)` if all coefficients have |c| < bound, `Choice(0)` otherwise.
    /// This keeps the result in `Choice` form so callers can decide when (or whether)
    /// to convert to `bool` (e.g., via [`check_norm`](Self::check_norm)).
    ///
    /// Non-positive bounds always return `Choice(0)` (fail).
    pub(crate) fn check_norm_ct(&self, bound: i32) -> subtle::Choice {
        use subtle::{ConditionallySelectable, ConstantTimeGreater};

        // Non-positive bounds: no coefficient can satisfy |c| < bound <= 0
        if bound <= 0 {
            return subtle::Choice::from(0u8);
        }

        let mut fail = subtle::Choice::from(0u8);
        let bound_u32 = bound as u32;

        for &c in &self.coeffs {
            // Compute |c| in constant time, handling both centered and reduced coefficients.
            let c_negative = (c as u32).ct_gt(&(i32::MAX as u32));
            let neg_c = (-(c as i64)) as u32;

            // For non-negative c, check if it represents a negative in reduced form.
            let c_u32 = c as u32;
            let half_q = ((Q - 1) / 2) as u32;
            let c_gt_half = c_u32.ct_gt(&half_q);
            let q_minus_c = (Q as u32).wrapping_sub(c_u32);

            // Select the absolute value.
            let abs_if_nonneg = u32::conditional_select(&c_u32, &q_minus_c, c_gt_half);
            let abs_t = u32::conditional_select(&abs_if_nonneg, &neg_c, c_negative);

            let exceeds = abs_t.ct_gt(&(bound_u32 - 1));
            fail |= exceeds;
        }

        !fail
    }

    /// Compute the infinity norm max |coeffs[i]|.
    pub fn norm_inf(&self) -> i32 {
        let mut max = 0;
        for &c in &self.coeffs {
            let mut t = freeze(c);
            if t > (Q - 1) / 2 {
                t = Q - t;
            }
            if t > max {
                max = t;
            }
        }
        max
    }
}

impl core::ops::Index<usize> for Poly {
    type Output = i32;

    fn index(&self, i: usize) -> &Self::Output {
        &self.coeffs[i]
    }
}

impl core::ops::IndexMut<usize> for Poly {
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        &mut self.coeffs[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_sub() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[0] = 100;
        a.coeffs[1] = 200;
        b.coeffs[0] = 50;
        b.coeffs[1] = 100;

        let c = a.add(&b);
        assert_eq!(c.coeffs[0], 150);
        assert_eq!(c.coeffs[1], 300);

        let d = a.sub(&b);
        assert_eq!(d.coeffs[0], 50);
        assert_eq!(d.coeffs[1], 100);
    }

    #[test]
    fn test_poly_check_norm() {
        let mut p = Poly::zero();
        assert!(p.check_norm(1));

        p.coeffs[0] = 100;
        assert!(p.check_norm(101));
        assert!(!p.check_norm(100));
    }

    #[test]
    fn test_poly_check_norm_reduced_form() {
        // Coefficients in reduced form [0, Q-1] where values > (Q-1)/2
        // represent negative numbers in centered form.
        let mut p = Poly::zero();

        // Q - 50 represents -50 in centered form, so |c| = 50
        p.coeffs[0] = Q - 50;
        assert!(p.check_norm(51));
        assert!(!p.check_norm(50));

        // Test with failing coefficient in non-first position
        let mut p2 = Poly::zero();
        p2.coeffs[200] = Q - 1; // represents -1, |c| = 1
        assert!(p2.check_norm(2));
        assert!(!p2.check_norm(1));
    }

    #[test]
    fn test_poly_check_norm_non_positive_bound() {
        let p = Poly::zero();
        // bound <= 0 should always fail (no coefficient can satisfy |c| < 0)
        assert!(!p.check_norm(0));
        assert!(!p.check_norm(-1));
        assert!(!p.check_norm(i32::MIN));

        // check_norm_ct should agree
        assert!(!bool::from(p.check_norm_ct(0)));
        assert!(!bool::from(p.check_norm_ct(-1)));
    }

    #[test]
    fn test_poly_norm_inf() {
        let mut p = Poly::zero();
        p.coeffs[0] = 50;
        p.coeffs[100] = 200;
        p.coeffs[200] = Q - 100; // This is -100 in centered form

        let norm = p.norm_inf();
        assert_eq!(norm, 200);
    }
}
