//! Sampling functions for ML-KEM.
//!
//! This module implements FIPS 203 Algorithm 7 (SampleNTT) for sampling
//! polynomials uniformly from the XOF output.

// Sampling internals used by matrix/key generation; not directly exposed.
#![allow(dead_code)]

use crate::hash::Xof;
use crate::params::common::Q;
use crate::poly::Poly;

/// Sample a polynomial in NTT domain from XOF output (FIPS 203 Algorithm 7).
///
/// Uses rejection sampling to uniformly sample coefficients in [0, q-1].
/// The XOF output is interpreted as pairs of 12-bit values, and values >= q
/// are rejected.
///
/// # Arguments
/// * `xof` - XOF instance initialized with the appropriate seed
///
/// # Returns
/// Polynomial with coefficients uniformly distributed in [0, q-1]
///
/// # Note
/// The output is already in NTT domain (it represents evaluations at
/// roots of unity, not polynomial coefficients).
pub fn sample_ntt(xof: &mut Xof) -> Poly {
    let mut poly = Poly::new();
    let mut j = 0;

    while j < 256 {
        let mut buf = [0u8; 3];
        xof.squeeze(&mut buf);

        // Extract two 12-bit values from 3 bytes
        let d1 = (buf[0] as u16) | (((buf[1] as u16) & 0x0F) << 8);
        let d2 = ((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4);

        // Rejection sampling: only accept values < q
        if d1 < Q {
            poly.coeffs[j] = d1 as i16;
            j += 1;
        }
        if j < 256 && d2 < Q {
            poly.coeffs[j] = d2 as i16;
            j += 1;
        }
    }

    poly
}

/// Sample a polynomial in NTT domain with given seed and indices.
///
/// Convenience function that creates the XOF and samples the polynomial.
///
/// # Arguments
/// * `rho` - 32-byte public seed
/// * `i` - Row index
/// * `j` - Column index
///
/// # Returns
/// Polynomial uniformly sampled in NTT domain
pub fn sample_ntt_from_seed(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Xof::new(rho, i, j);
    sample_ntt(&mut xof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_ntt_deterministic() {
        let rho = [0x42u8; 32];
        let poly1 = sample_ntt_from_seed(&rho, 0, 0);
        let poly2 = sample_ntt_from_seed(&rho, 0, 0);

        for i in 0..256 {
            assert_eq!(poly1.coeffs[i], poly2.coeffs[i]);
        }
    }

    #[test]
    fn test_sample_ntt_coefficients_in_range() {
        let rho = [0x42u8; 32];
        let poly = sample_ntt_from_seed(&rho, 0, 0);

        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < Q as i16,
                "Coefficient {} = {} out of range [0, {})",
                i,
                poly.coeffs[i],
                Q
            );
        }
    }

    #[test]
    fn test_sample_ntt_different_indices() {
        let rho = [0x42u8; 32];
        let poly1 = sample_ntt_from_seed(&rho, 0, 0);
        let poly2 = sample_ntt_from_seed(&rho, 0, 1);
        let poly3 = sample_ntt_from_seed(&rho, 1, 0);

        // Should be different polynomials
        let same_01 = poly1
            .coeffs
            .iter()
            .zip(poly2.coeffs.iter())
            .all(|(a, b)| a == b);
        let same_02 = poly1
            .coeffs
            .iter()
            .zip(poly3.coeffs.iter())
            .all(|(a, b)| a == b);

        assert!(!same_01, "poly(0,0) should differ from poly(0,1)");
        assert!(!same_02, "poly(0,0) should differ from poly(1,0)");
    }

    #[test]
    fn test_sample_ntt_different_rho() {
        let rho1 = [0x00u8; 32];
        let rho2 = [0x01u8; 32];
        let poly1 = sample_ntt_from_seed(&rho1, 0, 0);
        let poly2 = sample_ntt_from_seed(&rho2, 0, 0);

        let same = poly1
            .coeffs
            .iter()
            .zip(poly2.coeffs.iter())
            .all(|(a, b)| a == b);
        assert!(!same, "Different rho should produce different polynomials");
    }

    #[test]
    fn test_sample_ntt_fills_all_coefficients() {
        let rho = [0x42u8; 32];
        let poly = sample_ntt_from_seed(&rho, 0, 0);

        // Check that we have 256 non-trivial coefficients
        // (statistically very unlikely to have 256 zeros)
        let nonzero_count = poly.coeffs.iter().filter(|&&c| c != 0).count();
        assert!(
            nonzero_count > 200,
            "Expected most coefficients to be nonzero, got {}",
            nonzero_count
        );
    }
}
