//! Packing functions for ML-DSA
//!
//! Encode/decode polynomials, keys, and signatures.

use crate::poly::{Poly, N};
use crate::rounding::D;

/// Pack polynomial with coefficients in [0, 2^10 - 1] (t1).
pub fn pack_t1(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 320);

    for i in 0..N / 4 {
        let t0 = poly.coeffs[4 * i] as u32;
        let t1 = poly.coeffs[4 * i + 1] as u32;
        let t2 = poly.coeffs[4 * i + 2] as u32;
        let t3 = poly.coeffs[4 * i + 3] as u32;

        out[5 * i] = t0 as u8;
        out[5 * i + 1] = ((t0 >> 8) | (t1 << 2)) as u8;
        out[5 * i + 2] = ((t1 >> 6) | (t2 << 4)) as u8;
        out[5 * i + 3] = ((t2 >> 4) | (t3 << 6)) as u8;
        out[5 * i + 4] = (t3 >> 2) as u8;
    }
}

/// Unpack polynomial with coefficients in [0, 2^10 - 1] (t1).
pub fn unpack_t1(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 320);

    for i in 0..N / 4 {
        poly.coeffs[4 * i] = ((input[5 * i] as i32) | ((input[5 * i + 1] as i32) << 8)) & 0x3FF;
        poly.coeffs[4 * i + 1] =
            (((input[5 * i + 1] as i32) >> 2) | ((input[5 * i + 2] as i32) << 6)) & 0x3FF;
        poly.coeffs[4 * i + 2] =
            (((input[5 * i + 2] as i32) >> 4) | ((input[5 * i + 3] as i32) << 4)) & 0x3FF;
        poly.coeffs[4 * i + 3] =
            (((input[5 * i + 3] as i32) >> 6) | ((input[5 * i + 4] as i32) << 2)) & 0x3FF;
    }
}

/// Pack polynomial with coefficients in [-2^(D-1), 2^(D-1)] (t0).
pub fn pack_t0(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 416);

    for i in 0..N / 8 {
        let mut t = [0i32; 8];
        for j in 0..8 {
            // Map to [0, 2^13 - 1]
            t[j] = (1 << (D - 1)) - poly.coeffs[8 * i + j];
        }

        out[13 * i] = t[0] as u8;
        out[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
        out[13 * i + 2] = (t[1] >> 3) as u8;
        out[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
        out[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
        out[13 * i + 5] = (t[3] >> 1) as u8;
        out[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
        out[13 * i + 7] = (t[4] >> 4) as u8;
        out[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
        out[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
        out[13 * i + 10] = (t[6] >> 2) as u8;
        out[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
        out[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack polynomial with coefficients in [-2^(D-1), 2^(D-1)] (t0).
///
/// Byte layout (8 coefficients * 13 bits = 104 bits = 13 bytes):
/// - byte[0] = t0[0-7]
/// - byte[1] = t0[8-12] | t1[0-2]<<5
/// - byte[2] = t1[3-10]
/// - byte[3] = t1[11-12] | t2[0-5]<<2
/// - byte[4] = t2[6-12] | t3[0]<<7
/// - byte[5] = t3[1-8]
/// - byte[6] = t3[9-12] | t4[0-3]<<4
/// - byte[7] = t4[4-11]
/// - byte[8] = t4[12] | t5[0-6]<<1
/// - byte[9] = t5[7-12] | t6[0-1]<<6
/// - byte[10] = t6[2-9]
/// - byte[11] = t6[10-12] | t7[0-4]<<3
/// - byte[12] = t7[5-12]
pub fn unpack_t0(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 416);

    for i in 0..N / 8 {
        // Coeff 0: t0 from bytes 0-1
        poly.coeffs[8 * i] = (input[13 * i] as i32) | ((input[13 * i + 1] as i32) << 8);
        poly.coeffs[8 * i] &= 0x1FFF;

        // Coeff 1: t1 from bytes 1-3
        poly.coeffs[8 * i + 1] = ((input[13 * i + 1] as i32) >> 5)
            | ((input[13 * i + 2] as i32) << 3)
            | ((input[13 * i + 3] as i32) << 11);
        poly.coeffs[8 * i + 1] &= 0x1FFF;

        // Coeff 2: t2 from bytes 3-4
        poly.coeffs[8 * i + 2] =
            ((input[13 * i + 3] as i32) >> 2) | ((input[13 * i + 4] as i32) << 6);
        poly.coeffs[8 * i + 2] &= 0x1FFF;

        // Coeff 3: t3 from bytes 4-6
        poly.coeffs[8 * i + 3] = ((input[13 * i + 4] as i32) >> 7)
            | ((input[13 * i + 5] as i32) << 1)
            | ((input[13 * i + 6] as i32) << 9);
        poly.coeffs[8 * i + 3] &= 0x1FFF;

        // Coeff 4: t4 from bytes 6-8
        poly.coeffs[8 * i + 4] = ((input[13 * i + 6] as i32) >> 4)
            | ((input[13 * i + 7] as i32) << 4)
            | ((input[13 * i + 8] as i32) << 12);
        poly.coeffs[8 * i + 4] &= 0x1FFF;

        // Coeff 5: t5 from bytes 8-9
        poly.coeffs[8 * i + 5] = ((input[13 * i + 8] as i32) >> 1)
            | ((input[13 * i + 9] as i32) << 7);
        poly.coeffs[8 * i + 5] &= 0x1FFF;

        // Coeff 6: t6 from bytes 9-11
        poly.coeffs[8 * i + 6] = ((input[13 * i + 9] as i32) >> 6)
            | ((input[13 * i + 10] as i32) << 2)
            | ((input[13 * i + 11] as i32) << 10);
        poly.coeffs[8 * i + 6] &= 0x1FFF;

        // Coeff 7: t7 from bytes 11-12
        poly.coeffs[8 * i + 7] = ((input[13 * i + 11] as i32) >> 3)
            | ((input[13 * i + 12] as i32) << 5);
        poly.coeffs[8 * i + 7] &= 0x1FFF;

        // Map back to centered representation
        for j in 0..8 {
            poly.coeffs[8 * i + j] = (1 << (D - 1)) - poly.coeffs[8 * i + j];
        }
    }
}

/// Pack polynomial with coefficients in [-eta, eta] (eta = 2).
pub fn pack_eta2(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 96);

    for i in 0..N / 8 {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = (2 - poly.coeffs[8 * i + j]) as u8;
        }

        out[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
        out[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        out[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}

/// Unpack polynomial with coefficients in [-eta, eta] (eta = 2).
pub fn unpack_eta2(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 96);

    for i in 0..N / 8 {
        poly.coeffs[8 * i] = (input[3 * i] & 0x07) as i32;
        poly.coeffs[8 * i + 1] = ((input[3 * i] >> 3) & 0x07) as i32;
        poly.coeffs[8 * i + 2] = ((input[3 * i] >> 6) | ((input[3 * i + 1] << 2) & 0x07)) as i32;
        poly.coeffs[8 * i + 3] = ((input[3 * i + 1] >> 1) & 0x07) as i32;
        poly.coeffs[8 * i + 4] = ((input[3 * i + 1] >> 4) & 0x07) as i32;
        poly.coeffs[8 * i + 5] =
            ((input[3 * i + 1] >> 7) | ((input[3 * i + 2] << 1) & 0x07)) as i32;
        poly.coeffs[8 * i + 6] = ((input[3 * i + 2] >> 2) & 0x07) as i32;
        poly.coeffs[8 * i + 7] = ((input[3 * i + 2] >> 5) & 0x07) as i32;

        for j in 0..8 {
            poly.coeffs[8 * i + j] = 2 - poly.coeffs[8 * i + j];
        }
    }
}

/// Pack polynomial with coefficients in [-eta, eta] (eta = 4).
pub fn pack_eta4(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 128);

    for i in 0..N / 2 {
        let t0 = (4 - poly.coeffs[2 * i]) as u8;
        let t1 = (4 - poly.coeffs[2 * i + 1]) as u8;
        out[i] = t0 | (t1 << 4);
    }
}

/// Unpack polynomial with coefficients in [-eta, eta] (eta = 4).
pub fn unpack_eta4(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 128);

    for i in 0..N / 2 {
        poly.coeffs[2 * i] = (input[i] & 0x0F) as i32;
        poly.coeffs[2 * i + 1] = (input[i] >> 4) as i32;

        poly.coeffs[2 * i] = 4 - poly.coeffs[2 * i];
        poly.coeffs[2 * i + 1] = 4 - poly.coeffs[2 * i + 1];
    }
}

/// Pack z polynomial (gamma1 = 2^17).
pub fn pack_z_17(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 576);

    for i in 0..N / 4 {
        let mut t = [0i32; 4];
        for j in 0..4 {
            t[j] = (1 << 17) - poly.coeffs[4 * i + j];
        }

        out[9 * i] = t[0] as u8;
        out[9 * i + 1] = (t[0] >> 8) as u8;
        out[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
        out[9 * i + 3] = (t[1] >> 6) as u8;
        out[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
        out[9 * i + 5] = (t[2] >> 4) as u8;
        out[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
        out[9 * i + 7] = (t[3] >> 2) as u8;
        out[9 * i + 8] = (t[3] >> 10) as u8;
    }
}

/// Unpack z polynomial (gamma1 = 2^17).
pub fn unpack_z_17(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 576);

    for i in 0..N / 4 {
        poly.coeffs[4 * i] = (input[9 * i] as i32)
            | ((input[9 * i + 1] as i32) << 8)
            | ((input[9 * i + 2] as i32) << 16);
        poly.coeffs[4 * i] &= 0x3FFFF;

        poly.coeffs[4 * i + 1] = ((input[9 * i + 2] as i32) >> 2)
            | ((input[9 * i + 3] as i32) << 6)
            | ((input[9 * i + 4] as i32) << 14);
        poly.coeffs[4 * i + 1] &= 0x3FFFF;

        poly.coeffs[4 * i + 2] = ((input[9 * i + 4] as i32) >> 4)
            | ((input[9 * i + 5] as i32) << 4)
            | ((input[9 * i + 6] as i32) << 12);
        poly.coeffs[4 * i + 2] &= 0x3FFFF;

        poly.coeffs[4 * i + 3] = ((input[9 * i + 6] as i32) >> 6)
            | ((input[9 * i + 7] as i32) << 2)
            | ((input[9 * i + 8] as i32) << 10);
        poly.coeffs[4 * i + 3] &= 0x3FFFF;

        // Map back from [0, 2^18-1] to [-2^17, 2^17]
        for j in 0..4 {
            poly.coeffs[4 * i + j] = (1 << 17) - poly.coeffs[4 * i + j];
        }
    }
}

/// Pack z polynomial (gamma1 = 2^19).
pub fn pack_z_19(poly: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 640);

    for i in 0..N / 4 {
        let mut t = [0i32; 4];
        for j in 0..4 {
            t[j] = (1 << 19) - poly.coeffs[4 * i + j];
        }

        out[10 * i] = t[0] as u8;
        out[10 * i + 1] = (t[0] >> 8) as u8;
        out[10 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
        out[10 * i + 3] = (t[1] >> 4) as u8;
        out[10 * i + 4] = (t[1] >> 12) as u8;
        out[10 * i + 5] = t[2] as u8;
        out[10 * i + 6] = (t[2] >> 8) as u8;
        out[10 * i + 7] = ((t[2] >> 16) | (t[3] << 4)) as u8;
        out[10 * i + 8] = (t[3] >> 4) as u8;
        out[10 * i + 9] = (t[3] >> 12) as u8;
    }
}

/// Unpack z polynomial (gamma1 = 2^19).
pub fn unpack_z_19(input: &[u8], poly: &mut Poly) {
    debug_assert_eq!(input.len(), 640);

    for i in 0..N / 4 {
        poly.coeffs[4 * i] = (input[10 * i] as i32)
            | ((input[10 * i + 1] as i32) << 8)
            | ((input[10 * i + 2] as i32) << 16);
        poly.coeffs[4 * i] &= 0xFFFFF;

        poly.coeffs[4 * i + 1] = ((input[10 * i + 2] as i32) >> 4)
            | ((input[10 * i + 3] as i32) << 4)
            | ((input[10 * i + 4] as i32) << 12);
        poly.coeffs[4 * i + 1] &= 0xFFFFF;

        poly.coeffs[4 * i + 2] = (input[10 * i + 5] as i32)
            | ((input[10 * i + 6] as i32) << 8)
            | ((input[10 * i + 7] as i32) << 16);
        poly.coeffs[4 * i + 2] &= 0xFFFFF;

        poly.coeffs[4 * i + 3] = ((input[10 * i + 7] as i32) >> 4)
            | ((input[10 * i + 8] as i32) << 4)
            | ((input[10 * i + 9] as i32) << 12);
        poly.coeffs[4 * i + 3] &= 0xFFFFF;

        // Map back from [0, 2^20-1] to [-2^19, 2^19]
        for j in 0..4 {
            poly.coeffs[4 * i + j] = (1 << 19) - poly.coeffs[4 * i + j];
        }
    }
}

/// Pack w1 polynomial (gamma2 for compression).
pub fn pack_w1(poly: &Poly, gamma2: i32, out: &mut [u8]) {
    if gamma2 == 261888 {
        // 4 bits per coefficient
        debug_assert_eq!(out.len(), 128);
        for i in 0..N / 2 {
            out[i] = (poly.coeffs[2 * i] | (poly.coeffs[2 * i + 1] << 4)) as u8;
        }
    } else {
        // 6 bits per coefficient
        debug_assert_eq!(out.len(), 192);
        for i in 0..N / 4 {
            out[3 * i] = (poly.coeffs[4 * i] | (poly.coeffs[4 * i + 1] << 6)) as u8;
            out[3 * i + 1] = ((poly.coeffs[4 * i + 1] >> 2) | (poly.coeffs[4 * i + 2] << 4)) as u8;
            out[3 * i + 2] = ((poly.coeffs[4 * i + 2] >> 4) | (poly.coeffs[4 * i + 3] << 2)) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_t1() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = (i as i32) % 1024;
        }

        let mut packed = [0u8; 320];
        pack_t1(&poly, &mut packed);

        let mut unpacked = Poly::zero();
        unpack_t1(&packed, &mut unpacked);

        assert_eq!(poly.coeffs, unpacked.coeffs);
    }

    #[test]
    fn test_pack_unpack_eta2() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = ((i as i32) % 5) - 2; // [-2, 2]
        }

        let mut packed = [0u8; 96];
        pack_eta2(&poly, &mut packed);

        let mut unpacked = Poly::zero();
        unpack_eta2(&packed, &mut unpacked);

        assert_eq!(poly.coeffs, unpacked.coeffs);
    }

    #[test]
    fn test_pack_unpack_eta4() {
        let mut poly = Poly::zero();
        for i in 0..N {
            poly.coeffs[i] = ((i as i32) % 9) - 4; // [-4, 4]
        }

        let mut packed = [0u8; 128];
        pack_eta4(&poly, &mut packed);

        let mut unpacked = Poly::zero();
        unpack_eta4(&packed, &mut unpacked);

        assert_eq!(poly.coeffs, unpacked.coeffs);
    }

    #[test]
    fn test_pack_unpack_t0() {
        // t0 coefficients should be in (-2^(D-1), 2^(D-1)] = (-4096, 4096] = [-4095, 4096]
        // This is the range produced by Power2Round per FIPS 204
        let mut poly = Poly::zero();
        for i in 0..N {
            // Use a variety of values in the valid range [-4095, 4096]
            poly.coeffs[i] = ((i as i32 * 37) % 8192) - 4095;
        }

        let mut packed = [0u8; 416];
        pack_t0(&poly, &mut packed);

        let mut unpacked = Poly::zero();
        unpack_t0(&packed, &mut unpacked);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "Mismatch at index {}: expected {}, got {}",
                i, poly.coeffs[i], unpacked.coeffs[i]
            );
        }
    }

    #[test]
    fn test_pack_unpack_t0_edge_cases() {
        // Test specific edge cases
        let mut poly = Poly::zero();

        // Test values at boundaries
        poly.coeffs[0] = -4095;  // min valid
        poly.coeffs[1] = 4096;   // max valid
        poly.coeffs[2] = 0;
        poly.coeffs[3] = 1;
        poly.coeffs[4] = -1;
        poly.coeffs[5] = 2000;
        poly.coeffs[6] = -2000;
        poly.coeffs[7] = 4095;

        // Fill the rest with pattern values
        for i in 8..N {
            poly.coeffs[i] = ((i as i32 * 17) % 8192) - 4095;
        }

        let mut packed = [0u8; 416];
        pack_t0(&poly, &mut packed);

        let mut unpacked = Poly::zero();
        unpack_t0(&packed, &mut unpacked);

        for i in 0..N {
            assert_eq!(
                poly.coeffs[i], unpacked.coeffs[i],
                "Mismatch at index {}: expected {}, got {}",
                i, poly.coeffs[i], unpacked.coeffs[i]
            );
        }
    }
}
