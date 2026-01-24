//! NEON SIMD optimizations for ML-DSA (aarch64)
//!
//! This module provides NEON-accelerated implementations of performance-critical
//! operations. All operations maintain constant-time properties.
//!
//! # Performance
//!
//! NEON provides 128-bit registers, allowing:
//! - 4x i32 operations in parallel
//! - 2x i64 operations in parallel
//!
//! # Safety
//!
//! All functions require NEON support (standard on aarch64).

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

use crate::poly::N;
use crate::reduce::{Q, QINV};

/// Montgomery multiplication on 4 values in parallel using NEON.
///
/// Computes r = a * b * R^(-1) mod q for 4 coefficient pairs.
///
/// # Safety
///
/// Requires NEON support (standard on aarch64).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
pub unsafe fn montgomery_mul_4x(a: int32x4_t, b: int32x4_t) -> int32x4_t {
    let q = vdupq_n_s32(Q);
    let qinv = vdupq_n_s32(QINV);

    // Compute a * b as 64-bit products
    // vmull_s32 computes 32x32->64 for the low 2 lanes
    // vmull_high_s32 computes 32x32->64 for the high 2 lanes

    let ab_lo = vmull_s32(vget_low_s32(a), vget_low_s32(b));
    let ab_hi = vmull_high_s32(a, b);

    // t = (ab mod 2^32) * QINV mod 2^32
    // Extract low 32 bits of each 64-bit product
    let ab_lo_32 = vmovn_s64(ab_lo);
    let ab_hi_32 = vmovn_s64(ab_hi);
    let ab_32 = vcombine_s32(ab_lo_32, ab_hi_32);

    let t = vmulq_s32(ab_32, qinv);

    // t * q (64-bit products)
    let tq_lo = vmull_s32(vget_low_s32(t), vget_low_s32(q));
    let tq_hi = vmull_high_s32(t, q);

    // (ab - tq) >> 32
    let diff_lo = vsubq_s64(ab_lo, tq_lo);
    let diff_hi = vsubq_s64(ab_hi, tq_hi);

    // Extract high 32 bits (arithmetic right shift by 32)
    let result_lo = vshrn_n_s64(diff_lo, 32);
    let result_hi = vshrn_n_s64(diff_hi, 32);

    vcombine_s32(result_lo, result_hi)
}

/// Pointwise multiplication of two polynomials using NEON.
///
/// Computes r[i] = a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires NEON support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a.as_ptr().add(i));
        let vb = vld1q_s32(b.as_ptr().add(i));

        let vr = montgomery_mul_4x(va, vb);

        vst1q_s32(r.as_mut_ptr().add(i), vr);
    }
}

/// Pointwise multiply-accumulate using NEON.
///
/// Computes r[i] += a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires NEON support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a.as_ptr().add(i));
        let vb = vld1q_s32(b.as_ptr().add(i));
        let vr_old = vld1q_s32(r.as_ptr().add(i));

        let product = montgomery_mul_4x(va, vb);
        let vr_new = vaddq_s32(vr_old, product);

        vst1q_s32(r.as_mut_ptr().add(i), vr_new);
    }
}

/// Polynomial addition using NEON.
///
/// Computes r[i] = a[i] + b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires NEON support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_add(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a.as_ptr().add(i));
        let vb = vld1q_s32(b.as_ptr().add(i));

        let vr = vaddq_s32(va, vb);

        vst1q_s32(r.as_mut_ptr().add(i), vr);
    }
}

/// Polynomial subtraction using NEON.
///
/// Computes r[i] = a[i] - b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires NEON support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_sub(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a.as_ptr().add(i));
        let vb = vld1q_s32(b.as_ptr().add(i));

        let vr = vsubq_s32(va, vb);

        vst1q_s32(r.as_mut_ptr().add(i), vr);
    }
}

/// Conditional add q using NEON.
///
/// For each coefficient: if a[i] < 0, add q.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn caddq_neon(a: &mut [i32; N]) {
    let q = vdupq_n_s32(Q);

    for i in (0..N).step_by(4) {
        let va = vld1q_s32(a.as_ptr().add(i));

        // mask = -1 if a < 0, 0 otherwise
        let mask = vshrq_n_s32(va, 31);

        // result = a + (q & mask)
        let add = vandq_s32(q, mask);
        let vr = vaddq_s32(va, add);

        vst1q_s32(a.as_mut_ptr().add(i), vr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_montgomery_mul_equivalence() {
        let a = [123456i32, 234567, 345678, 456789];
        let b = [111111i32, 222222, 333333, 444444];

        // Scalar reference
        let mut expected = [0i32; 4];
        for i in 0..4 {
            expected[i] = crate::reduce::montgomery_mul(a[i], b[i]);
        }

        // SIMD version
        let mut result = [0i32; 4];
        unsafe {
            let va = vld1q_s32(a.as_ptr());
            let vb = vld1q_s32(b.as_ptr());
            let vr = montgomery_mul_4x(va, vb);
            vst1q_s32(result.as_mut_ptr(), vr);
        }

        assert_eq!(expected, result);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_pointwise_mul_equivalence() {
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        for i in 0..N {
            a[i] = (i as i32 * 12345) % Q;
            b[i] = (i as i32 * 67890) % Q;
        }

        // Scalar reference
        let mut expected = [0i32; N];
        for i in 0..N {
            expected[i] = crate::reduce::montgomery_mul(a[i], b[i]);
        }

        // SIMD version
        let mut result = [0i32; N];
        unsafe {
            pointwise_mul(&mut result, &a, &b);
        }

        assert_eq!(expected, result);
    }
}
