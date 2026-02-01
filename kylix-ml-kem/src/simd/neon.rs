//! NEON SIMD optimizations for ML-KEM (aarch64)
//!
//! This module provides NEON-accelerated implementations of performance-critical
//! operations. All operations maintain constant-time properties.
//!
//! # Performance
//!
//! NEON provides 128-bit registers, allowing:
//! - 8x i16 operations in parallel (ML-KEM's coefficient size)
//!
//! # Safety
//!
//! All functions require NEON support (always available on aarch64).

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
// Use explicit a = a + b form for consistency with ntt.rs scalar implementation
#![allow(clippy::assign_op_pattern)]
// Allow dead_code for poly_add/poly_sub which are implemented but not yet
// integrated into the main poly.rs. These will be used in a future PR to
// accelerate polynomial arithmetic throughout the crate.
#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use crate::ntt::ZETAS;
use crate::params::common::N;
use crate::reduce::INV_N_MONT;

/// ML-KEM modulus q = 3329
const Q: i16 = 3329;

/// Q inverse mod 2^16: q^(-1) mod 2^16 = -3327
const QINV: i16 = -3327i16;

/// Barrett constant V: floor(2^26 / q + 0.5) = 20159
const BARRETT_V: i16 = 20159;

// ============================================================================
// Core reduction operations for 16-bit coefficients
// ============================================================================

/// Compute high 16 bits of signed 16x16->32 multiply for 8 values.
///
/// Returns (a * b) >> 16 for each pair.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn mulhi_s16(a: int16x8_t, b: int16x8_t) -> int16x8_t {
    // Split into halves
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let b_lo = vget_low_s16(b);
    let b_hi = vget_high_s16(b);

    // Widening multiply: 16x16 -> 32
    let prod_lo = vmull_s16(a_lo, b_lo); // 4x i32
    let prod_hi = vmull_s16(a_hi, b_hi); // 4x i32

    // Extract high 16 bits (>> 16)
    let hi_lo = vshrn_n_s32(prod_lo, 16); // 4x i16
    let hi_hi = vshrn_n_s32(prod_hi, 16); // 4x i16
    vcombine_s16(hi_lo, hi_hi)
}

/// Efficient Barrett reduction on 8 values in parallel.
///
/// Uses pqcrystals/kyber-style approach with 16-bit operations.
/// Pattern: mulhi -> shift -> mul -> sub
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn barrett_reduce_8x(a: int16x8_t) -> int16x8_t {
    let v = vdupq_n_s16(BARRETT_V);
    let q = vdupq_n_s16(Q);

    // t = (a * v) >> 16 (high 16 bits of signed multiply)
    let t = mulhi_s16(a, v);

    // t = t >> 10 (total shift: >> 26)
    let t = vshrq_n_s16(t, 10);

    // t = t * q (low 16 bits)
    let t = vmulq_s16(t, q);

    // result = a - t
    vsubq_s16(a, t)
}

// ============================================================================
// Core Montgomery operations for 16-bit coefficients
// ============================================================================

/// Montgomery multiplication on 8 values in parallel.
///
/// Computes r = a * b * R^(-1) mod q for 8 coefficient pairs where R = 2^16.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn montgomery_mul_8x(
    a: int16x8_t,
    b: int16x8_t,
    q: int16x8_t,
    qinv: int16x8_t,
) -> int16x8_t {
    // Step 1-2: Compute a * b, get low and high 16 bits
    // vqdmulhq_s16 gives approximately (a * b * 2) >> 16, but we need exact high bits
    // Use widening multiply instead
    let ab_lo = vmulq_s16(a, b); // Low 16 bits of each product

    // For high bits, we need to do widening multiply and extract high parts
    // Split into low and high halves
    let a_lo = vget_low_s16(a);
    let a_hi = vget_high_s16(a);
    let b_lo = vget_low_s16(b);
    let b_hi = vget_high_s16(b);

    // Widening multiply: 16x16 -> 32
    let ab_wide_lo = vmull_s16(a_lo, b_lo); // 4x i32
    let ab_wide_hi = vmull_s16(a_hi, b_hi); // 4x i32

    // Extract high 16 bits
    let ab_hi_lo = vshrn_n_s32(ab_wide_lo, 16); // 4x i16
    let ab_hi_hi = vshrn_n_s32(ab_wide_hi, 16); // 4x i16
    let ab_hi = vcombine_s16(ab_hi_lo, ab_hi_hi);

    // Step 3: t = ab_lo * QINV mod 2^16
    let t = vmulq_s16(ab_lo, qinv);

    // Step 4: tq_hi = (t * q) >> 16
    let t_lo = vget_low_s16(t);
    let t_hi = vget_high_s16(t);
    let q_lo = vget_low_s16(q);
    let q_hi = vget_high_s16(q);

    let tq_wide_lo = vmull_s16(t_lo, q_lo);
    let tq_wide_hi = vmull_s16(t_hi, q_hi);

    let tq_hi_lo = vshrn_n_s32(tq_wide_lo, 16);
    let tq_hi_hi = vshrn_n_s32(tq_wide_hi, 16);
    let tq_hi = vcombine_s16(tq_hi_lo, tq_hi_hi);

    // Step 5: result = ab_hi - tq_hi
    vsubq_s16(ab_hi, tq_hi)
}

// ============================================================================
// Butterfly operations
// ============================================================================

/// Forward NTT butterfly for len >= 8.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn butterfly_neon(a: &mut [i16; N], start: usize, len: usize, zeta: i16) {
    let zeta_v = vdupq_n_s16(zeta);
    let q = vdupq_n_s16(Q);
    let qinv = vdupq_n_s16(QINV);

    let mut j = start;
    while j + 8 <= start + len {
        let a_lo = vld1q_s16(a.as_ptr().add(j));
        let a_hi = vld1q_s16(a.as_ptr().add(j + len));

        // t = zeta * a[j + len] (Montgomery multiplication)
        let t = montgomery_mul_8x(zeta_v, a_hi, q, qinv);

        // a[j] = a[j] + t
        let new_lo = vaddq_s16(a_lo, t);
        // a[j+len] = a[j] - t
        let new_hi = vsubq_s16(a_lo, t);

        vst1q_s16(a.as_mut_ptr().add(j), new_lo);
        vst1q_s16(a.as_mut_ptr().add(j + len), new_hi);

        j += 8;
    }

    // Scalar fallback for any remaining elements when len is not a multiple of 8.
    // In the ML-KEM NTT (N = 256), all len values >= 8 are powers of 2 and thus
    // multiples of 8, so this loop is not entered in current usage, but it is
    // kept for correctness if butterfly_neon is ever used with other lengths.
    while j < start + len {
        let t = crate::reduce::montgomery_mul(zeta, a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        j += 1;
    }
}

/// Inverse NTT butterfly for len >= 8.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn inv_butterfly_neon(a: &mut [i16; N], start: usize, len: usize, zeta: i16) {
    let zeta_v = vdupq_n_s16(zeta);
    let q = vdupq_n_s16(Q);
    let qinv = vdupq_n_s16(QINV);

    let mut j = start;
    while j + 8 <= start + len {
        let t = vld1q_s16(a.as_ptr().add(j));
        let a_hi = vld1q_s16(a.as_ptr().add(j + len));

        // a[j] = barrett_reduce(t + a[j+len]) to prevent overflow
        let sum = vaddq_s16(t, a_hi);
        let new_lo = barrett_reduce_8x(sum);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = vsubq_s16(t, a_hi);
        let new_hi = montgomery_mul_8x(zeta_v, diff, q, qinv);

        vst1q_s16(a.as_mut_ptr().add(j), new_lo);
        vst1q_s16(a.as_mut_ptr().add(j + len), new_hi);

        j += 8;
    }

    // Scalar fallback for any remaining elements when len is not a multiple of 8.
    // In the ML-KEM NTT (N = 256), all len values >= 8 are powers of 2 and thus
    // multiples of 8, so this loop is not entered in current usage, but it is
    // kept for correctness if inv_butterfly_neon is ever used with other lengths.
    while j < start + len {
        let t = a[j];
        a[j] = crate::reduce::barrett_reduce(t.wrapping_add(a[j + len]));
        a[j + len] = crate::reduce::montgomery_mul(zeta, t.wrapping_sub(a[j + len]));
        j += 1;
    }
}

// ============================================================================
// NTT implementations
// ============================================================================

/// Forward NTT using NEON.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn ntt_neon(a: &mut [i16; N]) {
    let mut k: usize = 1;
    let mut len: usize = 128;

    // len >= 8: use SIMD
    while len >= 8 {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            butterfly_neon(a, start, len, zeta);
            start += 2 * len;
        }
        len >>= 1;
    }

    // len=4, 2: use scalar operations
    for len in [4usize, 2] {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = crate::reduce::montgomery_mul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            start += 2 * len;
        }
    }
}

/// Inverse NTT using NEON.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn inv_ntt_neon(a: &mut [i16; N]) {
    let mut k: usize = 127;

    // len=2, 4: use scalar operations
    for len in [2usize, 4] {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            for j in start..(start + len) {
                let t = a[j];
                a[j] = crate::reduce::barrett_reduce(t.wrapping_add(a[j + len]));
                a[j + len] = crate::reduce::montgomery_mul(-zeta, t.wrapping_sub(a[j + len]));
            }
            start += 2 * len;
        }
    }

    // len >= 8: use SIMD
    let mut len: usize = 8;
    while len <= 128 {
        let mut start: usize = 0;
        while start < N {
            let zeta = -ZETAS[k];
            k = k.wrapping_sub(1);
            inv_butterfly_neon(a, start, len, zeta);
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by N^(-1) in Montgomery form using SIMD
    let inv_n = vdupq_n_s16(INV_N_MONT);
    let q = vdupq_n_s16(Q);
    let qinv = vdupq_n_s16(QINV);

    for i in (0..N).step_by(8) {
        let va = vld1q_s16(a.as_ptr().add(i));
        let vr = montgomery_mul_8x(inv_n, va, q, qinv);
        vst1q_s16(a.as_mut_ptr().add(i), vr);
    }
}

// ============================================================================
// Basemul SIMD operations
// ============================================================================

/// Accumulate polynomial basemul: r += a * b in NTT domain using NEON.
///
/// Processes 8 coefficients (2 coefficient groups, 4 basemul operations) per iteration.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_basemul_acc_neon(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    let q = vdupq_n_s16(Q);
    let qinv = vdupq_n_s16(QINV);

    // Process 8 coefficients (2 groups) per iteration
    // 256 coefficients / 8 = 32 iterations
    for i in 0..32 {
        let base = i * 8;
        // ZETAS[64..128] contain the precomputed twiddle factors for basemul.
        // The NTT uses ZETAS[0..64] for butterfly operations, while basemul
        // uses ZETAS[64..128] for the polynomial ring structure (X^2 - zeta).
        let zeta_idx = 64 + i * 2;

        // Load 8 coefficients from a, b, and r
        let va = vld1q_s16(a.as_ptr().add(base));
        let vb = vld1q_s16(b.as_ptr().add(base));
        let vr = vld1q_s16(r.as_ptr().add(base));

        // Prepare zeta vector: [z0, z0, -z0, -z0, z1, z1, -z1, -z1]
        let z0 = ZETAS[zeta_idx];
        let z1 = ZETAS[zeta_idx + 1];
        let zeta_arr: [i16; 8] = [z0, z0, -z0, -z0, z1, z1, -z1, -z1];
        let zeta_v = vld1q_s16(zeta_arr.as_ptr());

        // Compute basemul for all 4 pairs
        let result = basemul_4x_neon(va, vb, zeta_v, q, qinv);

        // Accumulate: r += result
        let vr_new = vaddq_s16(vr, result);
        vst1q_s16(r.as_mut_ptr().add(base), vr_new);
    }
}

/// Compute 4 basemul operations in parallel using NEON.
///
/// Input layout: [a0, a1, a2, a3, a4, a5, a6, a7]
/// Each pair (a[2i], a[2i+1]) is a 2-coefficient input for basemul.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn basemul_4x_neon(
    a: int16x8_t,
    b: int16x8_t,
    zeta: int16x8_t,
    q: int16x8_t,
    qinv: int16x8_t,
) -> int16x8_t {
    // Extract even indices: [a0, a2, a4, a6] -> duplicate to [a0, a0, a2, a2, a4, a4, a6, a6]
    // Extract odd indices:  [a1, a3, a5, a7]
    let a_even = shuffle_even_8(a);
    let a_odd = shuffle_odd_8(a);
    let b_even = shuffle_even_8(b);
    let b_odd = shuffle_odd_8(b);

    // Extract even zetas
    let zeta_even = shuffle_even_8(zeta);

    // r_even = a_even*b_even + a_odd*b_odd*zeta
    let t1 = montgomery_mul_8x(a_even, b_even, q, qinv);
    let t2 = montgomery_mul_8x(a_odd, b_odd, q, qinv);
    let t3 = montgomery_mul_8x(t2, zeta_even, q, qinv);
    let r_even = vaddq_s16(t1, t3);

    // r_odd = a_even*b_odd + a_odd*b_even
    let t4 = montgomery_mul_8x(a_even, b_odd, q, qinv);
    let t5 = montgomery_mul_8x(a_odd, b_even, q, qinv);
    let r_odd = vaddq_s16(t4, t5);

    // Interleave back: [r0, r1, r2, r3, ...]
    interleave_8(r_even, r_odd)
}

/// Extract even-indexed i16 values using NEON.
/// [a0, a1, a2, a3, a4, a5, a6, a7] -> [a0, a2, a4, a6, a0, a2, a4, a6]
///
/// The lower 4 elements contain the even values, replicated to upper 4 for consistent
/// vector width in subsequent operations.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn shuffle_even_8(a: int16x8_t) -> int16x8_t {
    // Use table lookup (vqtbl1q_u8) to extract bytes of even-indexed i16 values.
    // Each i16 occupies 2 bytes in little-endian order:
    //   i16[0] = bytes 0,1   i16[1] = bytes 2,3
    //   i16[2] = bytes 4,5   i16[3] = bytes 6,7
    //   i16[4] = bytes 8,9   i16[5] = bytes 10,11
    //   i16[6] = bytes 12,13 i16[7] = bytes 14,15
    //
    // We want even indices (0, 2, 4, 6), so bytes: 0,1, 4,5, 8,9, 12,13
    // Packed as little-endian u64: 0x0D0C_0908_0504_0100
    // Upper 64 bits use 0xFF (invalid index) which zeroes output bytes.
    let tbl_idx = vcombine_u8(
        vcreate_u8(0x0D0C_0908_0504_0100_u64), // Bytes for i16[0,2,4,6]
        vcreate_u8(0xFFFF_FFFF_FFFF_FFFF_u64), // Invalid indices -> zero
    );

    let a_bytes: uint8x16_t = vreinterpretq_u8_s16(a);
    let result_bytes = vqtbl1q_u8(a_bytes, tbl_idx);

    // Lower 64 bits now contain [a0, a2, a4, a6]. Replicate to upper half
    // so all 8 lanes contain valid data for subsequent operations.
    // Note: We use replication instead of zeroing the upper half because
    // interleave_8 only uses the lower 4 elements anyway, and replication
    // provides consistent behavior if the result is used elsewhere.
    let lo = vget_low_s16(vreinterpretq_s16_u8(result_bytes));
    vcombine_s16(lo, lo)
}

/// Extract odd-indexed i16 values using NEON.
/// [a0, a1, a2, a3, a4, a5, a6, a7] -> [a1, a3, a5, a7, a1, a3, a5, a7]
///
/// The lower 4 elements contain the odd values, replicated to upper 4 for consistent
/// vector width in subsequent operations.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn shuffle_odd_8(a: int16x8_t) -> int16x8_t {
    // Use table lookup (vqtbl1q_u8) to extract bytes of odd-indexed i16 values.
    // Each i16 occupies 2 bytes in little-endian order:
    //   i16[1] = bytes 2,3   i16[3] = bytes 6,7
    //   i16[5] = bytes 10,11 i16[7] = bytes 14,15
    //
    // We want odd indices (1, 3, 5, 7), so bytes: 2,3, 6,7, 10,11, 14,15
    // Packed as little-endian u64: 0x0F0E_0B0A_0706_0302
    // Upper 64 bits use 0xFF (invalid index) which zeroes output bytes.
    let tbl_idx = vcombine_u8(
        vcreate_u8(0x0F0E_0B0A_0706_0302_u64), // Bytes for i16[1,3,5,7]
        vcreate_u8(0xFFFF_FFFF_FFFF_FFFF_u64), // Invalid indices -> zero
    );

    let a_bytes: uint8x16_t = vreinterpretq_u8_s16(a);
    let result_bytes = vqtbl1q_u8(a_bytes, tbl_idx);

    // Lower 64 bits now contain [a1, a3, a5, a7]. Replicate to upper half
    // so all 8 lanes contain valid data for subsequent operations.
    // Note: We use replication instead of zeroing the upper half because
    // interleave_8 only uses the lower 4 elements anyway, and replication
    // provides consistent behavior if the result is used elsewhere.
    let lo = vget_low_s16(vreinterpretq_s16_u8(result_bytes));
    vcombine_s16(lo, lo)
}

/// Interleave even and odd values: [e0, e1, e2, e3] + [o0, o1, o2, o3] -> [e0, o0, e1, o1, e2, o2, e3, o3]
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn interleave_8(even: int16x8_t, odd: int16x8_t) -> int16x8_t {
    // even and odd have valid values in lower 4 elements
    let even_lo = vget_low_s16(even);
    let odd_lo = vget_low_s16(odd);

    // vzip interleaves: [e0,e1,e2,e3] + [o0,o1,o2,o3] -> [e0,o0,e1,o1], [e2,o2,e3,o3]
    let zipped = vzip_s16(even_lo, odd_lo);

    vcombine_s16(zipped.0, zipped.1)
}

// ============================================================================
// Polynomial arithmetic
// ============================================================================

/// Polynomial addition using NEON.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_add(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in (0..N).step_by(8) {
        let va = vld1q_s16(a.as_ptr().add(i));
        let vb = vld1q_s16(b.as_ptr().add(i));

        let vr = vaddq_s16(va, vb);

        vst1q_s16(r.as_mut_ptr().add(i), vr);
    }
}

/// Polynomial subtraction using NEON.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_sub(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in (0..N).step_by(8) {
        let va = vld1q_s16(a.as_ptr().add(i));
        let vb = vld1q_s16(b.as_ptr().add(i));

        let vr = vsubq_s16(va, vb);

        vst1q_s16(r.as_mut_ptr().add(i), vr);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[cfg(target_arch = "aarch64")]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_simd_equivalence() {
        // Create test polynomial
        let mut poly_simd = [0i16; N];
        let mut poly_scalar = [0i16; N];
        for i in 0..N {
            let val = ((i * 17 + 31) % 3329) as i16;
            poly_simd[i] = val;
            poly_scalar[i] = val;
        }

        // SIMD NTT
        unsafe {
            ntt_neon(&mut poly_simd);
        }

        // Scalar NTT (call scalar function directly to avoid SIMD dispatch)
        crate::ntt::ntt_scalar(&mut poly_scalar);

        assert_eq!(poly_simd, poly_scalar, "NTT SIMD vs scalar mismatch");
    }

    #[test]
    fn test_inv_ntt_simd_equivalence() {
        // Create test polynomial in NTT domain
        let mut poly_simd = [0i16; N];
        let mut poly_scalar = [0i16; N];
        for i in 0..N {
            let val = ((i * 23 + 47) % 3329) as i16;
            poly_simd[i] = val;
            poly_scalar[i] = val;
        }

        // SIMD inverse NTT
        unsafe {
            inv_ntt_neon(&mut poly_simd);
        }

        // Scalar inverse NTT (call scalar function directly to avoid SIMD dispatch)
        crate::ntt::inv_ntt_scalar(&mut poly_scalar);

        // Compare mod Q (SIMD and scalar may use different canonical forms)
        for i in 0..N {
            let simd_val = crate::reduce::barrett_reduce_full(poly_simd[i]);
            let scalar_val = crate::reduce::barrett_reduce_full(poly_scalar[i]);
            assert_eq!(
                simd_val, scalar_val,
                "INVNTT SIMD vs scalar mismatch at index {}: {} vs {}",
                i, poly_simd[i], poly_scalar[i]
            );
        }
    }

    #[test]
    fn test_ntt_roundtrip() {
        // Create test polynomial
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = ((i * 13 + 7) % 3329) as i16;
        }
        let original = poly;

        // Forward NTT then inverse NTT
        unsafe {
            ntt_neon(&mut poly);
            inv_ntt_neon(&mut poly);
        }

        // Result should match original (after from_mont conversion)
        for (i, (&coeff, &orig)) in poly.iter().zip(original.iter()).enumerate() {
            let result = crate::reduce::barrett_reduce_full(crate::reduce::from_mont(coeff));
            let expected = crate::reduce::barrett_reduce_full(orig);
            assert_eq!(result, expected, "Roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn test_poly_add_equivalence() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = (i as i16) % 3329;
            b[i] = ((i * 2) as i16) % 3329;
        }

        let mut r_simd = [0i16; N];
        unsafe {
            poly_add(&mut r_simd, &a, &b);
        }

        // Scalar addition
        let mut r_scalar = [0i16; N];
        for i in 0..N {
            r_scalar[i] = a[i].wrapping_add(b[i]);
        }

        assert_eq!(r_simd, r_scalar, "Poly add SIMD vs scalar mismatch");
    }

    #[test]
    fn test_poly_sub_equivalence() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = ((i * 3) as i16) % 3329;
            b[i] = (i as i16) % 3329;
        }

        let mut r_simd = [0i16; N];
        unsafe {
            poly_sub(&mut r_simd, &a, &b);
        }

        // Scalar subtraction
        let mut r_scalar = [0i16; N];
        for i in 0..N {
            r_scalar[i] = a[i].wrapping_sub(b[i]);
        }

        assert_eq!(r_simd, r_scalar, "Poly sub SIMD vs scalar mismatch");
    }
}
