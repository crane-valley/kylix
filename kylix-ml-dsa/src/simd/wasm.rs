//! WASM SIMD128 optimizations for ML-DSA (wasm32)
//!
//! This module provides WASM SIMD128-accelerated implementations of
//! performance-critical operations. All operations maintain constant-time properties.
//!
//! # Performance
//!
//! WASM SIMD128 provides 128-bit registers, allowing:
//! - 4x i32 operations in parallel
//! - 2x i64 operations in parallel
//!
//! # Safety
//!
//! All functions require WASM SIMD128 support.
//! Compile with `RUSTFLAGS="-C target-feature=+simd128"`.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;

use crate::poly::N;
use crate::reduce::{Q, QINV};

/// Montgomery multiplication on 4 values in parallel using WASM SIMD128.
///
/// Computes r = a * b * R^(-1) mod q for 4 coefficient pairs.
///
/// # Safety
///
/// Requires WASM SIMD128 support.
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
#[inline]
pub unsafe fn montgomery_mul_4x(a: v128, b: v128) -> v128 {
    let q = i32x4_splat(Q);
    let qinv = i32x4_splat(QINV);

    // Compute a * b as 64-bit products
    // i64x2_extmul_low_i32x4: multiply lanes 0,1 -> i64x2
    // i64x2_extmul_high_i32x4: multiply lanes 2,3 -> i64x2
    let ab_lo = i64x2_extmul_low_i32x4(a, b);
    let ab_hi = i64x2_extmul_high_i32x4(a, b);

    // Extract low 32 bits of each 64-bit product for t calculation
    // Use shuffle to extract: [ab_lo[0] as i32, ab_lo[1] as i32, ab_hi[0] as i32, ab_hi[1] as i32]
    let ab_32 = i32x4_shuffle::<0, 2, 4, 6>(ab_lo, ab_hi);

    // t = ab_32 * QINV (wrapping multiply)
    let t = i32x4_mul(ab_32, qinv);

    // t * q (64-bit products)
    let tq_lo = i64x2_extmul_low_i32x4(t, q);
    let tq_hi = i64x2_extmul_high_i32x4(t, q);

    // (ab - tq) >> 32
    let diff_lo = i64x2_sub(ab_lo, tq_lo);
    let diff_hi = i64x2_sub(ab_hi, tq_hi);

    // Extract high 32 bits (arithmetic right shift by 32)
    let result_lo = i64x2_shr(diff_lo, 32);
    let result_hi = i64x2_shr(diff_hi, 32);

    // Pack back to i32x4: extract low 32 bits of each 64-bit lane
    i32x4_shuffle::<0, 2, 4, 6>(result_lo, result_hi)
}

/// Pointwise multiplication of two polynomials using WASM SIMD128.
///
/// Computes r[i] = a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires WASM SIMD128 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
pub unsafe fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = v128_load(a.as_ptr().add(i).cast());
        let vb = v128_load(b.as_ptr().add(i).cast());

        let vr = montgomery_mul_4x(va, vb);

        v128_store(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Pointwise multiply-accumulate using WASM SIMD128.
///
/// Computes r[i] += a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires WASM SIMD128 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
pub unsafe fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = v128_load(a.as_ptr().add(i).cast());
        let vb = v128_load(b.as_ptr().add(i).cast());
        let vr_old = v128_load(r.as_ptr().add(i).cast());

        let product = montgomery_mul_4x(va, vb);
        let vr_new = i32x4_add(vr_old, product);

        v128_store(r.as_mut_ptr().add(i).cast(), vr_new);
    }
}

/// Polynomial addition using WASM SIMD128.
///
/// Computes r[i] = a[i] + b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires WASM SIMD128 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
pub unsafe fn poly_add(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = v128_load(a.as_ptr().add(i).cast());
        let vb = v128_load(b.as_ptr().add(i).cast());

        let vr = i32x4_add(va, vb);

        v128_store(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Polynomial subtraction using WASM SIMD128.
///
/// Computes r[i] = a[i] - b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires WASM SIMD128 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
pub unsafe fn poly_sub(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(4) {
        let va = v128_load(a.as_ptr().add(i).cast());
        let vb = v128_load(b.as_ptr().add(i).cast());

        let vr = i32x4_sub(va, vb);

        v128_store(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Conditional add q using WASM SIMD128.
///
/// For each coefficient: if a[i] < 0, add q.
///
/// # Safety
///
/// Requires WASM SIMD128 support.
#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
pub unsafe fn caddq_wasm(a: &mut [i32; N]) {
    let q = i32x4_splat(Q);

    for i in (0..N).step_by(4) {
        let va = v128_load(a.as_ptr().add(i).cast());

        // mask = -1 if a < 0, 0 otherwise (arithmetic right shift by 31)
        let mask = i32x4_shr(va, 31);

        // result = a + (q & mask)
        let add = v128_and(q, mask);
        let vr = i32x4_add(va, add);

        v128_store(a.as_mut_ptr().add(i).cast(), vr);
    }
}

#[cfg(test)]
mod tests {
    // WASM tests need to be run with wasm-pack or similar
    // Skip for now as we can't run wasm32 tests in native environment
}
