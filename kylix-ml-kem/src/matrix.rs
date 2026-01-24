//! Matrix operations for ML-KEM.
//!
//! This module provides functions for sampling the public matrix A
//! and computing matrix-vector products.

// Matrix operations are used internally; public API is via variant modules.
#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]

use crate::poly::{poly_basemul_acc, Poly};
use crate::polyvec::PolyVec;
use crate::sample::sample_ntt_from_seed;

/// Sample the K x K matrix A from seed rho.
///
/// Each entry A[i][j] is sampled from XOF(rho || j || i) in NTT domain.
/// Note: FIPS 203 uses column-major indexing, so the XOF is initialized
/// with (j, i) not (i, j).
///
/// # Arguments
/// * `rho` - 32-byte public seed
/// * `transpose` - If true, sample A^T instead of A
///
/// # Returns
/// K x K matrix of polynomials in NTT domain
pub fn sample_matrix<const K: usize>(rho: &[u8; 32], transpose: bool) -> [[Poly; K]; K] {
    let mut a: [[Poly; K]; K] = core::array::from_fn(|_| core::array::from_fn(|_| Poly::new()));

    for i in 0..K {
        for j in 0..K {
            if transpose {
                // A^T[i][j] = A[j][i], so sample with (j, i)
                a[i][j] = sample_ntt_from_seed(rho, j as u8, i as u8);
            } else {
                // A[i][j] sampled from XOF(rho || j || i)
                a[i][j] = sample_ntt_from_seed(rho, i as u8, j as u8);
            }
            // Coefficients are already in normal form [0, q-1] from sample_ntt
        }
    }

    a
}

/// Multiply matrix A by vector s: result = A * s.
///
/// Both A and s must be in NTT domain. The result is also in NTT domain.
///
/// # Arguments
/// * `a` - K x K matrix in NTT domain
/// * `s` - K-vector in NTT domain
///
/// # Returns
/// K-vector result = A * s in NTT domain
pub fn matrix_vec_mul<const K: usize>(a: &[[Poly; K]; K], s: &PolyVec<K>) -> PolyVec<K> {
    let mut result = PolyVec::new();

    for i in 0..K {
        // result[i] = sum_j(A[i][j] * s[j])
        for j in 0..K {
            poly_basemul_acc(&mut result.polys[i], &a[i][j], &s.polys[j]);
        }
    }

    result
}

/// Multiply transpose of matrix A by vector r: result = A^T * r.
///
/// This is equivalent to sampling A^T and multiplying, but can be done
/// more efficiently by reordering the multiplication.
///
/// Both A and r must be in NTT domain. The result is also in NTT domain.
///
/// # Arguments
/// * `a` - K x K matrix in NTT domain (will be transposed)
/// * `r` - K-vector in NTT domain
///
/// # Returns
/// K-vector result = A^T * r in NTT domain
pub fn matrix_vec_mul_transpose<const K: usize>(a: &[[Poly; K]; K], r: &PolyVec<K>) -> PolyVec<K> {
    let mut result = PolyVec::new();

    for i in 0..K {
        // result[i] = sum_j(A^T[i][j] * r[j]) = sum_j(A[j][i] * r[j])
        for j in 0..K {
            poly_basemul_acc(&mut result.polys[i], &a[j][i], &r.polys[j]);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::common::Q;

    #[test]
    fn test_sample_matrix_deterministic() {
        let rho = [0x42u8; 32];
        let a1: [[Poly; 3]; 3] = sample_matrix(&rho, false);
        let a2: [[Poly; 3]; 3] = sample_matrix(&rho, false);

        for i in 0..3 {
            for j in 0..3 {
                for k in 0..256 {
                    assert_eq!(a1[i][j].coeffs[k], a2[i][j].coeffs[k]);
                }
            }
        }
    }

    #[test]
    fn test_sample_matrix_coefficients_in_range() {
        let rho = [0x42u8; 32];
        let a: [[Poly; 2]; 2] = sample_matrix(&rho, false);

        // Coefficients should be in range [0, q-1] after rejection sampling
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..256 {
                    assert!(
                        a[i][j].coeffs[k] >= 0 && a[i][j].coeffs[k] < Q as i16,
                        "A[{}][{}][{}] = {} out of range [0, q-1]",
                        i,
                        j,
                        k,
                        a[i][j].coeffs[k]
                    );
                }
            }
        }
    }

    #[test]
    fn test_sample_matrix_transpose() {
        let rho = [0x42u8; 32];
        let a: [[Poly; 2]; 2] = sample_matrix(&rho, false);
        let at: [[Poly; 2]; 2] = sample_matrix(&rho, true);

        // A^T[i][j] should equal A[j][i]
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..256 {
                    assert_eq!(
                        at[i][j].coeffs[k], a[j][i].coeffs[k],
                        "Transpose mismatch at [{},{}][{}]",
                        i, j, k
                    );
                }
            }
        }
    }

    #[test]
    fn test_matrix_vec_mul_zero() {
        let rho = [0x42u8; 32];
        let a: [[Poly; 2]; 2] = sample_matrix(&rho, false);
        let s: PolyVec<2> = PolyVec::new(); // Zero vector

        let result = matrix_vec_mul(&a, &s);

        // A * 0 = 0
        for i in 0..2 {
            for k in 0..256 {
                assert_eq!(result.polys[i].coeffs[k], 0);
            }
        }
    }

    #[test]
    fn test_matrix_vec_mul_transpose_equivalence() {
        let rho = [0x42u8; 32];
        let a: [[Poly; 2]; 2] = sample_matrix(&rho, false);
        let at: [[Poly; 2]; 2] = sample_matrix(&rho, true);

        // Create a test vector
        let mut r: PolyVec<2> = PolyVec::new();
        for i in 0..2 {
            for j in 0..256 {
                r.polys[i].coeffs[j] = ((i * 256 + j) % 100) as i16;
            }
        }
        // Put in NTT domain
        r.ntt();

        // A^T * r computed two ways should be the same
        let result1 = matrix_vec_mul(&at, &r);
        let result2 = matrix_vec_mul_transpose(&a, &r);

        for i in 0..2 {
            for k in 0..256 {
                assert_eq!(
                    result1.polys[i].coeffs[k], result2.polys[i].coeffs[k],
                    "Mismatch at [{}][{}]",
                    i, k
                );
            }
        }
    }
}
