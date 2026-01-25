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

/// Barrett constant: floor(2^26 / q) + 1 = 20159
const BARRETT_MUL: i32 = 20159;

// ============================================================================
// Core reduction operations for 16-bit coefficients
// ============================================================================

/// Barrett reduction on 8 values in parallel.
///
/// Computes a mod q for each value in the vector.
///
/// # Safety
///
/// Requires NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn barrett_reduce_8x(a: int16x8_t) -> int16x8_t {
    let v = BARRETT_MUL;
    let round = 1i32 << 25;
    let q32 = Q as i32;

    // Extend to 32-bit for each half
    let a_lo = vmovl_s16(vget_low_s16(a)); // 4x i32
    let a_hi = vmovl_s16(vget_high_s16(a)); // 4x i32

    let v_vec = vdupq_n_s32(v);
    let round_vec = vdupq_n_s32(round);
    let q_vec = vdupq_n_s32(q32);

    // t = (a * v + 2^25) >> 26
    let t_lo = vshrq_n_s32(vaddq_s32(vmulq_s32(a_lo, v_vec), round_vec), 26);
    let t_hi = vshrq_n_s32(vaddq_s32(vmulq_s32(a_hi, v_vec), round_vec), 26);

    // r = a - t * q
    let r_lo = vsubq_s32(a_lo, vmulq_s32(t_lo, q_vec));
    let r_hi = vsubq_s32(a_hi, vmulq_s32(t_hi, q_vec));

    // Pack back to 16-bit (narrowing)
    let r_lo_16 = vmovn_s32(r_lo); // 4x i16
    let r_hi_16 = vmovn_s32(r_hi); // 4x i16
    vcombine_s16(r_lo_16, r_hi_16)
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

    // Scalar fallback (note: for len >= 8, this loop is never entered since
    // len is always a power of 2 >= 8, so the SIMD loop processes all elements)
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

    // Scalar fallback (note: for len >= 8, this loop is never entered since
    // len is always a power of 2 >= 8, so the SIMD loop processes all elements)
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
