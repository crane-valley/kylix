//! Sampling functions for ML-DSA
//!
//! Implements ExpandA, ExpandS, ExpandMask, SampleInBall.

use crate::hash::{Shake128Xof, Shake256Xof};
use crate::poly::{Poly, N};
use crate::reduce::Q;

/// Rejection bound for sampling (23-bit)
const REJECTION_BOUND: i32 = Q;

/// Sample a uniform polynomial in NTT domain from SHAKE128.
///
/// Used for expanding matrix A.
pub fn sample_ntt(xof: &mut Shake128Xof) -> Poly {
    let mut poly = Poly::zero();
    let mut buf = [0u8; 3];
    let mut ctr = 0;

    while ctr < N {
        xof.squeeze(&mut buf);

        // Extract two 12-bit values from 3 bytes (for compatibility)
        // Actually for q=8380417, we need 23 bits
        // Use 3 bytes = 24 bits, extract one coefficient
        let t = (buf[0] as i32) | ((buf[1] as i32) << 8) | (((buf[2] & 0x7F) as i32) << 16);

        if t < REJECTION_BOUND {
            poly.coeffs[ctr] = t;
            ctr += 1;
        }
    }

    poly
}

/// Sample polynomial with coefficients in [-eta, eta] from SHAKE256.
///
/// Used for sampling secret vectors s1, s2.
pub fn sample_eta<const ETA: usize>(seed: &[u8], nonce: u16) -> Poly {
    let mut poly = Poly::zero();

    // Compute input: seed || nonce (little-endian)
    let mut input = [0u8; 66];
    input[..seed.len()].copy_from_slice(seed);
    input[seed.len()] = nonce as u8;
    input[seed.len() + 1] = (nonce >> 8) as u8;

    let mut xof = Shake256Xof::from_data(&input[..seed.len() + 2]);

    if ETA == 2 {
        // eta = 2: sample uniformly from {-2, -1, 0, 1, 2}
        // Per FIPS 204 Algorithm 15 (CoeffFromHalfByte for eta=2)
        // Use 4-bit nibbles, reject if >= 15, then compute t mod 5
        let mut buf = [0u8; 136];
        xof.squeeze(&mut buf);

        let mut pos = 0;
        let mut ctr = 0;
        while ctr < N && pos < buf.len() {
            let t0 = (buf[pos] & 0x0F) as i32;
            let t1 = (buf[pos] >> 4) as i32;
            pos += 1;

            // Reject values >= 15 to get uniform distribution over {0..14}
            // 15 values: 3 copies each of {0,1,2,3,4}
            if t0 < 15 {
                // Compute t0 mod 5 using: a = t - (205*t >> 10) * 5
                // 205/1024 ≈ 0.2 ≈ 1/5, so (205*t >> 10) ≈ floor(t/5)
                let a = t0 - (205 * t0 >> 10) * 5;
                // Map {0,1,2,3,4} to {2,1,0,-1,-2}
                poly.coeffs[ctr] = 2 - a;
                ctr += 1;
            }
            if ctr < N && t1 < 15 {
                let a = t1 - (205 * t1 >> 10) * 5;
                poly.coeffs[ctr] = 2 - a;
                ctr += 1;
            }
        }
    } else if ETA == 4 {
        // eta = 4: sample uniformly from {-4, -3, -2, -1, 0, 1, 2, 3, 4}
        // Per FIPS 204 Algorithm 15 (CoeffFromHalfByte for eta=4)
        // Use 4-bit nibbles, reject if >= 9
        let mut buf = [0u8; 136];
        xof.squeeze(&mut buf);

        let mut pos = 0;
        let mut ctr = 0;
        while ctr < N && pos < buf.len() {
            let t0 = (buf[pos] & 0x0F) as i32;
            let t1 = (buf[pos] >> 4) as i32;
            pos += 1;

            // Reject values >= 9 to get uniform distribution over {0..8}
            if t0 < 9 {
                // Map {0,1,2,3,4,5,6,7,8} to {4,3,2,1,0,-1,-2,-3,-4}
                poly.coeffs[ctr] = 4 - t0;
                ctr += 1;
            }
            if ctr < N && t1 < 9 {
                poly.coeffs[ctr] = 4 - t1;
                ctr += 1;
            }
        }
    }

    poly
}

/// Sample masking polynomial y with coefficients in [-gamma1+1, gamma1].
///
/// Used in signing for masking.
pub fn sample_mask(seed: &[u8; 64], nonce: u16, gamma1_bits: u32) -> Poly {
    let mut poly = Poly::zero();

    // Compute input: seed || nonce
    let mut input = [0u8; 66];
    input[..64].copy_from_slice(seed);
    input[64] = nonce as u8;
    input[65] = (nonce >> 8) as u8;

    let mut xof = Shake256Xof::from_data(&input);

    if gamma1_bits == 17 {
        // gamma1 = 2^17: use 18 bits per coefficient
        let mut buf = [0u8; 576]; // 256 * 18 / 8 = 576
        xof.squeeze(&mut buf);

        for i in 0..N {
            let idx = i * 18 / 8;
            let off = (i * 18) % 8;

            let mut t = (buf[idx] as i32) >> off;
            t |= (buf[idx + 1] as i32) << (8 - off);
            t |= ((buf[idx + 2] as i32) << (16 - off)) & 0x3FFFF;
            t &= 0x3FFFF;

            poly.coeffs[i] = (1 << 17) - t;
        }
    } else {
        // gamma1 = 2^19: use 20 bits per coefficient
        let mut buf = [0u8; 640]; // 256 * 20 / 8 = 640
        xof.squeeze(&mut buf);

        for i in 0..N {
            let idx = i * 20 / 8;
            let off = (i * 20) % 8;

            let mut t = (buf[idx] as i32) >> off;
            t |= (buf[idx + 1] as i32) << (8 - off);
            t |= (buf[idx + 2] as i32) << (16 - off);
            if off > 4 {
                t |= (buf[idx + 3] as i32) << (24 - off);
            }
            t &= 0xFFFFF;

            poly.coeffs[i] = (1 << 19) - t;
        }
    }

    poly
}

/// Sample challenge polynomial c with exactly tau coefficients in {-1, +1}.
///
/// The remaining coefficients are 0.
/// The seed length varies by security level (32, 48, or 64 bytes).
pub fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut poly = Poly::zero();
    let mut xof = Shake256Xof::from_data(seed);

    // First 8 bytes give the signs
    let mut signs = [0u8; 8];
    xof.squeeze(&mut signs);
    let mut sign_bits = u64::from_le_bytes(signs);

    let mut buf = [0u8; 1];
    for i in (N - tau)..N {
        // Sample j uniformly from [0, i]
        loop {
            xof.squeeze(&mut buf);
            let j = buf[0] as usize;
            if j <= i {
                // Swap and set coefficient
                poly.coeffs[i] = poly.coeffs[j];
                poly.coeffs[j] = if sign_bits & 1 != 0 { -1 } else { 1 };
                sign_bits >>= 1;
                break;
            }
        }
    }

    poly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_eta2() {
        let seed = [0u8; 32];
        let poly = sample_eta::<2>(&seed, 0);

        // Check all coefficients are in [-2, 2]
        for &c in &poly.coeffs {
            assert!(c >= -2 && c <= 2, "coefficient {c} out of range");
        }
    }

    #[test]
    fn test_sample_eta4() {
        let seed = [0u8; 32];
        let poly = sample_eta::<4>(&seed, 0);

        // Check all coefficients are in [-4, 4]
        for &c in &poly.coeffs {
            assert!(c >= -4 && c <= 4, "coefficient {c} out of range");
        }
    }

    #[test]
    fn test_sample_in_ball() {
        let seed = [0u8; 32];
        let tau = 39;
        let poly = sample_in_ball(&seed, tau);

        // Count non-zero coefficients
        let mut count = 0;
        for &c in &poly.coeffs {
            if c != 0 {
                assert!(c == 1 || c == -1, "non-zero coefficient must be +/-1");
                count += 1;
            }
        }
        assert_eq!(count, tau, "should have exactly tau non-zero coefficients");
    }

    #[test]
    fn test_sample_deterministic() {
        let seed = [42u8; 32];
        let poly1 = sample_eta::<2>(&seed, 0);
        let poly2 = sample_eta::<2>(&seed, 0);

        assert_eq!(poly1.coeffs, poly2.coeffs);
    }
}
