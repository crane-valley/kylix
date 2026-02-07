//! Polynomial vector operations for ML-DSA

use crate::ntt::pointwise_acc;
use crate::poly::Poly;
use subtle::Choice;
use zeroize::Zeroize;

/// Polynomial vector with K elements.
#[derive(Clone, Zeroize)]
pub struct PolyVecK<const K: usize> {
    pub polys: [Poly; K],
}

impl<const K: usize> Default for PolyVecK<K> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const K: usize> PolyVecK<K> {
    /// Create a zero vector.
    pub fn zero() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Forward NTT on all polynomials.
    pub fn ntt(&mut self) {
        for p in &mut self.polys {
            p.ntt();
        }
    }

    /// Inverse NTT on all polynomials.
    pub fn inv_ntt(&mut self) {
        for p in &mut self.polys {
            p.inv_ntt();
        }
    }

    /// Add two vectors.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..K {
            r.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        r
    }

    /// Add in place.
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..K {
            self.polys[i].add_assign(&other.polys[i]);
        }
    }

    /// Subtract two vectors.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..K {
            r.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        r
    }

    /// Reduce all coefficients.
    pub fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }

    /// Freeze all coefficients to [0, q-1].
    pub fn freeze(&mut self) {
        for p in &mut self.polys {
            p.freeze();
        }
    }

    /// Check infinity norm of all polynomials.
    ///
    /// Constant-time over the vector (no early return): uses
    /// `Poly::check_norm_ct` to accumulate a `Choice` and converts to `bool`
    /// only once at the end.
    pub fn check_norm(&self, bound: i32) -> bool {
        let mut pass = Choice::from(1u8);
        for p in &self.polys {
            pass &= p.check_norm_ct(bound);
        }
        bool::from(pass)
    }

    /// Conditional add Q.
    pub fn caddq(&mut self) {
        for p in &mut self.polys {
            p.caddq();
        }
    }
}

/// Polynomial vector with L elements.
#[derive(Clone, Zeroize)]
pub struct PolyVecL<const L: usize> {
    pub polys: [Poly; L],
}

impl<const L: usize> Default for PolyVecL<L> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const L: usize> PolyVecL<L> {
    /// Create a zero vector.
    pub fn zero() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    /// Forward NTT on all polynomials.
    pub fn ntt(&mut self) {
        for p in &mut self.polys {
            p.ntt();
        }
    }

    /// Inverse NTT on all polynomials.
    pub fn inv_ntt(&mut self) {
        for p in &mut self.polys {
            p.inv_ntt();
        }
    }

    /// Add two vectors.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..L {
            r.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        r
    }

    /// Subtract two vectors.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..L {
            r.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        r
    }

    /// Reduce all coefficients.
    pub fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }

    /// Freeze all coefficients to [0, q-1].
    pub fn freeze(&mut self) {
        for p in &mut self.polys {
            p.freeze();
        }
    }

    /// Check infinity norm of all polynomials.
    ///
    /// Constant-time over the vector (no early return): uses
    /// `Poly::check_norm_ct` to accumulate a `Choice` and converts to `bool`
    /// only once at the end.
    pub fn check_norm(&self, bound: i32) -> bool {
        let mut pass = Choice::from(1u8);
        for p in &self.polys {
            pass &= p.check_norm_ct(bound);
        }
        bool::from(pass)
    }

    /// Conditional add Q.
    pub fn caddq(&mut self) {
        for p in &mut self.polys {
            p.caddq();
        }
    }
}

/// Matrix A (K x L) in NTT domain.
pub struct Matrix<const K: usize, const L: usize> {
    pub rows: [PolyVecL<L>; K],
}

impl<const K: usize, const L: usize> Matrix<K, L> {
    /// Create a zero matrix.
    pub fn zero() -> Self {
        Self {
            rows: core::array::from_fn(|_| PolyVecL::zero()),
        }
    }

    /// Matrix-vector multiplication: t = A * s (in NTT domain).
    ///
    /// Both A and s must be in NTT domain.
    /// Returns t in NTT domain.
    pub fn mul_vec(&self, s: &PolyVecL<L>) -> PolyVecK<K> {
        let mut t = PolyVecK::zero();

        for i in 0..K {
            for j in 0..L {
                pointwise_acc(
                    &mut t.polys[i].coeffs,
                    &self.rows[i].polys[j].coeffs,
                    &s.polys[j].coeffs,
                );
            }
        }

        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyvec_add_sub() {
        let mut v1 = PolyVecK::<4>::zero();
        let mut v2 = PolyVecK::<4>::zero();

        v1.polys[0].coeffs[0] = 100;
        v2.polys[0].coeffs[0] = 50;

        let sum = v1.add(&v2);
        assert_eq!(sum.polys[0].coeffs[0], 150);

        let diff = v1.sub(&v2);
        assert_eq!(diff.polys[0].coeffs[0], 50);
    }

    #[test]
    fn test_polyvec_check_norm() {
        let mut v = PolyVecK::<4>::zero();
        assert!(v.check_norm(1));

        v.polys[0].coeffs[0] = 100;
        assert!(v.check_norm(101));
        assert!(!v.check_norm(100));
    }
}
