//! Polynomial vector operations for ML-KEM.
//!
//! This module provides the `PolyVec` type representing a vector of K polynomials,
//! along with arithmetic operations, NTT transforms, and serialization.

// Vector operations are used internally; some methods unused in certain configurations.
#![allow(dead_code)]
#![allow(clippy::wrong_self_convention)]

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encode::{poly_from_bytes, poly_to_bytes};
use crate::ntt::{inv_ntt, ntt};
use crate::params::common::N;
use crate::poly::{
    poly_add, poly_basemul_acc, poly_compress, poly_decompress, poly_reduce, poly_reduce_full, Poly,
};
use zeroize::Zeroize;

/// A vector of K polynomials.
///
/// Used to represent vectors s, e, r, t, u in ML-KEM.
#[derive(Clone)]
pub struct PolyVec<const K: usize> {
    /// The K polynomials in the vector.
    pub polys: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const K: usize> Zeroize for PolyVec<K> {
    fn zeroize(&mut self) {
        for poly in &mut self.polys {
            poly.zeroize();
        }
    }
}

impl<const K: usize> PolyVec<K> {
    /// Create a new zero polynomial vector.
    pub fn new() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::new()),
        }
    }

    /// Apply forward NTT to all polynomials in the vector.
    pub fn ntt(&mut self) {
        for poly in &mut self.polys {
            ntt(poly);
        }
    }

    /// Apply inverse NTT to all polynomials in the vector.
    pub fn inv_ntt(&mut self) {
        for poly in &mut self.polys {
            inv_ntt(poly);
        }
    }

    /// Reduce all coefficients using Barrett reduction.
    pub fn reduce(&mut self) {
        for poly in &mut self.polys {
            poly_reduce(poly);
        }
    }

    /// Reduce all coefficients to canonical form [0, q-1].
    pub fn reduce_full(&mut self) {
        for poly in &mut self.polys {
            poly_reduce_full(poly);
        }
    }

    /// Convert all polynomials from Montgomery form to standard form.
    ///
    /// Should be called after inv_ntt to convert back to standard coefficients.
    pub fn from_mont(&mut self) {
        use crate::poly::poly_from_mont;
        for poly in &mut self.polys {
            poly_from_mont(poly);
        }
    }

    /// Convert all polynomials to Montgomery form.
    ///
    /// Should be called before ntt on CBD-sampled polynomials.
    pub fn to_mont(&mut self) {
        use crate::poly::poly_to_mont;
        for poly in &mut self.polys {
            poly_to_mont(poly);
        }
    }

    /// Add two polynomial vectors element-wise.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..K {
            result.polys[i] = poly_add(&self.polys[i], &other.polys[i]);
        }
        result
    }

    /// Add another polynomial vector to self in place.
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..K {
            for j in 0..N {
                self.polys[i].coeffs[j] += other.polys[i].coeffs[j];
            }
        }
    }

    /// Compute inner product of two vectors in NTT domain.
    ///
    /// Returns sum of component-wise basemul: sum_i(self[i] * other[i]).
    /// Both vectors must be in NTT domain.
    pub fn inner_product(&self, other: &Self) -> Poly {
        let mut result = Poly::new();
        for i in 0..K {
            poly_basemul_acc(&mut result, &self.polys[i], &other.polys[i]);
        }
        result
    }

    /// Encode the polynomial vector to bytes (d=12, uncompressed).
    ///
    /// Each polynomial is encoded as 384 bytes, total K*384 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; K * 384];
        for i in 0..K {
            let poly_bytes = poly_to_bytes(&self.polys[i]);
            bytes[i * 384..(i + 1) * 384].copy_from_slice(&poly_bytes);
        }
        bytes
    }

    /// Decode a polynomial vector from bytes (d=12, uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = Self::new();
        for i in 0..K {
            let poly_bytes = &bytes[i * 384..(i + 1) * 384];
            result.polys[i] = poly_from_bytes(poly_bytes);
        }
        result
    }

    /// Compress the polynomial vector and encode to bytes.
    ///
    /// # Arguments
    /// * `du` - Compression parameter (10 or 11)
    ///
    /// # Returns
    /// Compressed bytes (K * 32 * du bytes)
    pub fn compress(&self, du: usize) -> Vec<u8> {
        let bytes_per_poly = 32 * du;
        let mut bytes = vec![0u8; K * bytes_per_poly];
        for i in 0..K {
            poly_compress(&self.polys[i], du as u32, &mut bytes[i * bytes_per_poly..]);
        }
        bytes
    }

    /// Decompress bytes to a polynomial vector.
    ///
    /// # Arguments
    /// * `bytes` - Compressed bytes
    /// * `du` - Compression parameter (10 or 11)
    pub fn decompress(bytes: &[u8], du: usize) -> Self {
        let mut result = Self::new();
        let bytes_per_poly = 32 * du;
        for i in 0..K {
            result.polys[i] = poly_decompress(
                &bytes[i * bytes_per_poly..(i + 1) * bytes_per_poly],
                du as u32,
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::common::Q;

    #[test]
    fn test_polyvec_new() {
        let pv: PolyVec<3> = PolyVec::new();
        for i in 0..3 {
            for j in 0..N {
                assert_eq!(pv.polys[i].coeffs[j], 0);
            }
        }
    }

    #[test]
    fn test_polyvec_add() {
        let mut pv1: PolyVec<2> = PolyVec::new();
        let mut pv2: PolyVec<2> = PolyVec::new();

        for i in 0..2 {
            for j in 0..N {
                pv1.polys[i].coeffs[j] = (j as i16) % 100;
                pv2.polys[i].coeffs[j] = ((j + 50) as i16) % 100;
            }
        }

        let result = pv1.add(&pv2);
        for i in 0..2 {
            for j in 0..N {
                assert_eq!(
                    result.polys[i].coeffs[j],
                    pv1.polys[i].coeffs[j] + pv2.polys[i].coeffs[j]
                );
            }
        }
    }

    #[test]
    fn test_polyvec_to_bytes_from_bytes_roundtrip() {
        let mut pv: PolyVec<3> = PolyVec::new();
        for i in 0..3 {
            for j in 0..N {
                pv.polys[i].coeffs[j] = ((i * N + j) as i16 * 13) % (Q as i16);
            }
        }

        let bytes = pv.to_bytes();
        assert_eq!(bytes.len(), 3 * 384);

        let recovered: PolyVec<3> = PolyVec::from_bytes(&bytes);
        for i in 0..3 {
            for j in 0..N {
                assert_eq!(pv.polys[i].coeffs[j], recovered.polys[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn test_polyvec_compress_decompress_roundtrip() {
        let mut pv: PolyVec<2> = PolyVec::new();
        for i in 0..2 {
            for j in 0..N {
                // Use values that compress well
                pv.polys[i].coeffs[j] = ((j as i16) * 13) % (Q as i16);
            }
        }

        // Test with du=10
        let compressed = pv.compress(10);
        assert_eq!(compressed.len(), 2 * 320);

        let decompressed: PolyVec<2> = PolyVec::decompress(&compressed, 10);

        // Compression is lossy, but should be close
        for i in 0..2 {
            for j in 0..N {
                let orig = pv.polys[i].coeffs[j];
                let recov = decompressed.polys[i].coeffs[j];
                let diff = (orig - recov).abs();
                // Maximum error for d=10 compression is about q/2^10 ≈ 3.25
                assert!(
                    diff < 5 || (Q as i16 - diff) < 5,
                    "Coefficient error too large: orig={}, recov={}, diff={}",
                    orig,
                    recov,
                    diff
                );
            }
        }
    }

    #[test]
    fn test_polyvec_inner_product() {
        // Simple test: inner product of unit vectors
        let mut pv1: PolyVec<2> = PolyVec::new();
        let mut pv2: PolyVec<2> = PolyVec::new();

        // Set some coefficients
        pv1.polys[0].coeffs[0] = 1;
        pv2.polys[0].coeffs[0] = 2;

        // Need to be in NTT domain for inner_product
        pv1.ntt();
        pv2.ntt();

        let result = pv1.inner_product(&pv2);

        // Result should be nonzero
        let has_nonzero = result.coeffs.iter().any(|&c| c != 0);
        assert!(has_nonzero);
    }

    #[test]
    fn test_polyvec_zeroize() {
        let mut pv: PolyVec<2> = PolyVec::new();
        for i in 0..2 {
            for j in 0..N {
                pv.polys[i].coeffs[j] = 42;
            }
        }

        pv.zeroize();

        for i in 0..2 {
            for j in 0..N {
                assert_eq!(pv.polys[i].coeffs[j], 0);
            }
        }
    }
}
