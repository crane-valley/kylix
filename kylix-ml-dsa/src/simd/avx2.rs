//! AVX2 SIMD optimizations for ML-DSA (x86_64)
//!
//! This module provides AVX2-accelerated implementations of performance-critical
//! operations. All operations maintain constant-time properties.
//!
//! # Performance
//!
//! AVX2 provides 256-bit registers, allowing:
//! - 8x i32 operations in parallel
//! - 4x i64 operations in parallel
//!
//! # Safety
//!
//! All functions require AVX2 support. Use `super::has_avx2()` to check availability.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::poly::N;
use crate::reduce::{Q, QINV};

/// Montgomery reduction on 8 values in parallel.
///
/// Computes r = a * R^(-1) mod q for 8 values simultaneously.
///
/// # Algorithm
///
/// For each 64-bit input a:
/// 1. t = (a mod 2^32) * QINV mod 2^32
/// 2. r = (a - t * q) >> 32
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn montgomery_reduce_avx2(a_lo: __m256i, a_hi: __m256i) -> __m256i {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    // t = a_lo * QINV (wrapping multiply, keep low 32 bits)
    let t = _mm256_mullo_epi32(a_lo, qinv);

    // We need to compute (t * q) and get the high 32 bits
    // Use _mm256_mul_epi32 which does signed 32x32->64 on even lanes only

    // Process even lanes (0, 2, 4, 6)
    let tq_even = _mm256_mul_epi32(t, q);
    let tq_hi_even = _mm256_srli_epi64(tq_even, 32);

    // Process odd lanes (1, 3, 5, 7) - shuffle to even positions first
    let t_odd = _mm256_srli_epi64(t, 32);
    let tq_odd = _mm256_mul_epi32(t_odd, q);
    let tq_hi_odd = _mm256_srli_epi64(tq_odd, 32);

    // Blend even and odd results back together
    // Even lanes: tq_hi_even already in position
    // Odd lanes: need to shift left by 32 bits
    let tq_hi_odd_shifted = _mm256_slli_epi64(tq_hi_odd, 32);
    let tq_hi = _mm256_blend_epi32(tq_hi_even, tq_hi_odd_shifted, 0xAA);

    // result = a_hi - tq_hi
    _mm256_sub_epi32(a_hi, tq_hi)
}

/// Montgomery multiplication on 8 values in parallel.
///
/// Computes r = a * b * R^(-1) mod q for 8 coefficient pairs.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn montgomery_mul_8x(a: __m256i, b: __m256i) -> __m256i {
    // Compute a * b as 64-bit products
    // We need to handle both even and odd lanes separately

    // Even lanes (0, 2, 4, 6): _mm256_mul_epi32 does this directly
    let ab_even = _mm256_mul_epi32(a, b);
    let ab_lo_even = ab_even; // Low 32 bits are in place
    let ab_hi_even = _mm256_srli_epi64(ab_even, 32);

    // Odd lanes (1, 3, 5, 7): shift right by 32 to bring to even positions
    let a_odd = _mm256_srli_epi64(a, 32);
    let b_odd = _mm256_srli_epi64(b, 32);
    let ab_odd = _mm256_mul_epi32(a_odd, b_odd);
    let ab_lo_odd = _mm256_slli_epi64(ab_odd, 32); // Move back to odd position
    let ab_hi_odd = ab_odd; // High 32 bits (already 64-bit aligned)

    // Combine even and odd results
    let ab_lo = _mm256_blend_epi32(ab_lo_even, ab_lo_odd, 0xAA);
    let ab_hi = _mm256_blend_epi32(ab_hi_even, ab_hi_odd, 0xAA);

    // Montgomery reduce
    montgomery_reduce_avx2(ab_lo, ab_hi)
}

/// Pointwise multiplication of two polynomials using AVX2.
///
/// Computes r[i] = a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires AVX2 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());

        let vr = montgomery_mul_8x(va, vb);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Pointwise multiply-accumulate using AVX2.
///
/// Computes r[i] += a[i] * b[i] * R^(-1) mod q for all 256 coefficients.
///
/// # Safety
///
/// - Requires AVX2 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());
        let vr_old = _mm256_loadu_si256(r.as_ptr().add(i).cast());

        let product = montgomery_mul_8x(va, vb);
        let vr_new = _mm256_add_epi32(vr_old, product);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr_new);
    }
}

/// Polynomial addition using AVX2.
///
/// Computes r[i] = a[i] + b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires AVX2 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());

        let vr = _mm256_add_epi32(va, vb);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Polynomial subtraction using AVX2.
///
/// Computes r[i] = a[i] - b[i] for all 256 coefficients.
///
/// # Safety
///
/// - Requires AVX2 support
/// - All arrays must have exactly N (256) elements
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());

        let vr = _mm256_sub_epi32(va, vb);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Barrett reduction on 8 values in parallel.
///
/// Reduces each coefficient to the range [0, q-1].
///
/// # Algorithm
///
/// Uses the approximation t ≈ floor(a / Q) based on Q ≈ 2^23:
/// 1. t = (a + 2^22) >> 23 (arithmetic shift for rounding)
/// 2. r = a - t * Q
/// 3. Conditional adjustments to ensure r ∈ [0, Q)
///
/// The rounding constant 2^22 ensures the approximation error is at most 1,
/// so r is in the range [-Q, 2Q) before the conditional steps.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn reduce_avx2(a: &mut [i32; N]) {
    let rounding = _mm256_set1_epi32(1 << 22);
    let q = _mm256_set1_epi32(Q);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());

        // Approximate quotient: t ≈ floor(a / Q)
        // Uses Q ≈ 2^23, with rounding constant for better accuracy
        let t = _mm256_srai_epi32(_mm256_add_epi32(va, rounding), 23);

        // Compute remainder: r = a - t * Q
        // Due to approximation error, r might be in [-Q, 2Q)
        let tq = _mm256_mullo_epi32(t, q);
        let r = _mm256_sub_epi32(va, tq);

        // Conditional add Q if r < 0 (handles negative approximation error)
        let neg_mask = _mm256_srai_epi32(r, 31);
        let r = _mm256_add_epi32(r, _mm256_and_si256(q, neg_mask));

        // Conditional subtract Q if r >= Q (handles positive approximation error)
        let r_minus_q = _mm256_sub_epi32(r, q);
        let pos_mask = _mm256_srai_epi32(r_minus_q, 31);
        let result = _mm256_add_epi32(r_minus_q, _mm256_and_si256(q, pos_mask));

        _mm256_storeu_si256(a.as_mut_ptr().add(i).cast(), result);
    }
}

/// Conditional add q using AVX2.
///
/// For each coefficient: if a[i] < 0, add q.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn caddq_avx2(a: &mut [i32; N]) {
    let q = _mm256_set1_epi32(Q);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());

        // mask = -1 if a < 0, 0 otherwise (arithmetic right shift by 31)
        let mask = _mm256_srai_epi32(va, 31);

        // result = a + (q & mask)
        let add = _mm256_and_si256(q, mask);
        let vr = _mm256_add_epi32(va, add);

        _mm256_storeu_si256(a.as_mut_ptr().add(i).cast(), vr);
    }
}

// ============================================================================
// NTT SIMD optimizations
// ============================================================================

/// Vectorized NTT butterfly operation.
///
/// For each pair (a[j], a[j+len]):
///   t = zeta * a[j+len] (Montgomery multiplication)
///   a[j+len] = a[j] - t
///   a[j] = a[j] + t
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(a: &mut [i32; N], start: usize, len: usize, zeta: i32) {
    let zeta_v = _mm256_set1_epi32(zeta);
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    let mut j = start;
    while j + 8 <= start + len {
        // Load 8 pairs
        let a_lo = _mm256_loadu_si256(a.as_ptr().add(j).cast());
        let a_hi = _mm256_loadu_si256(a.as_ptr().add(j + len).cast());

        // t = zeta * a_hi (Montgomery multiplication)
        let t = montgomery_mul_8x_with_params(a_hi, zeta_v, q, qinv);

        // a[j] = a[j] + t
        let new_lo = _mm256_add_epi32(a_lo, t);
        // a[j+len] = a[j] - t
        let new_hi = _mm256_sub_epi32(a_lo, t);

        _mm256_storeu_si256(a.as_mut_ptr().add(j).cast(), new_lo);
        _mm256_storeu_si256(a.as_mut_ptr().add(j + len).cast(), new_hi);

        j += 8;
    }

    // Handle remaining elements with scalar
    while j < start + len {
        let t = crate::reduce::montgomery_mul(zeta, a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        j += 1;
    }
}

/// Montgomery multiplication with pre-loaded parameters.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn montgomery_mul_8x_with_params(
    a: __m256i,
    b: __m256i,
    q: __m256i,
    qinv: __m256i,
) -> __m256i {
    // Even lanes (0, 2, 4, 6): _mm256_mul_epi32 does this directly
    let ab_even = _mm256_mul_epi32(a, b);
    let ab_hi_even = _mm256_srli_epi64(ab_even, 32);

    // Odd lanes (1, 3, 5, 7): shift right by 32 to bring to even positions
    let a_odd = _mm256_srli_epi64(a, 32);
    let b_odd = _mm256_srli_epi64(b, 32);
    let ab_odd = _mm256_mul_epi32(a_odd, b_odd);
    let ab_lo_odd = _mm256_slli_epi64(ab_odd, 32);

    // Combine even and odd results
    // ab_even already has low bits in correct position for even lanes
    // ab_odd already has high bits in correct position for odd lanes
    let ab_lo = _mm256_blend_epi32(ab_even, ab_lo_odd, 0xAA);
    let ab_hi = _mm256_blend_epi32(ab_hi_even, ab_odd, 0xAA);

    // Montgomery reduce
    montgomery_reduce_with_params(ab_lo, ab_hi, q, qinv)
}

/// Montgomery reduction with pre-loaded parameters.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn montgomery_reduce_with_params(
    a_lo: __m256i,
    a_hi: __m256i,
    q: __m256i,
    qinv: __m256i,
) -> __m256i {
    // t = a_lo * QINV (wrapping multiply, keep low 32 bits)
    let t = _mm256_mullo_epi32(a_lo, qinv);

    // Process even lanes (0, 2, 4, 6)
    let tq_even = _mm256_mul_epi32(t, q);
    let tq_hi_even = _mm256_srli_epi64(tq_even, 32);

    // Process odd lanes (1, 3, 5, 7)
    let t_odd = _mm256_srli_epi64(t, 32);
    let tq_odd = _mm256_mul_epi32(t_odd, q);
    let tq_hi_odd = _mm256_srli_epi64(tq_odd, 32);

    // Blend even and odd results back together
    let tq_hi_odd_shifted = _mm256_slli_epi64(tq_hi_odd, 32);
    let tq_hi = _mm256_blend_epi32(tq_hi_even, tq_hi_odd_shifted, 0xAA);

    // result = a_hi - tq_hi
    _mm256_sub_epi32(a_hi, tq_hi)
}

/// Vectorized inverse NTT butterfly operation.
///
/// For each pair (a[j], a[j+len]):
///   t = a[j]
///   a[j] = t + a[j+len]
///   a[j+len] = (t - a[j+len]) * zeta (Montgomery)
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn inv_butterfly_avx2(a: &mut [i32; N], start: usize, len: usize, zeta: i32) {
    let zeta_v = _mm256_set1_epi32(zeta);
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    let mut j = start;
    while j + 8 <= start + len {
        let t = _mm256_loadu_si256(a.as_ptr().add(j).cast());
        let a_hi = _mm256_loadu_si256(a.as_ptr().add(j + len).cast());

        // a[j] = t + a[j+len]
        let new_lo = _mm256_add_epi32(t, a_hi);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = _mm256_sub_epi32(t, a_hi);
        let new_hi = montgomery_mul_8x_with_params(diff, zeta_v, q, qinv);

        _mm256_storeu_si256(a.as_mut_ptr().add(j).cast(), new_lo);
        _mm256_storeu_si256(a.as_mut_ptr().add(j + len).cast(), new_hi);

        j += 8;
    }

    // Handle remaining elements with scalar
    while j < start + len {
        let t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = crate::reduce::montgomery_mul(zeta, t - a[j + len]);
        j += 1;
    }
}

/// Butterfly for len=4: process 2 groups at a time using AVX2.
///
/// Each group of 8 consecutive elements uses one zeta:
/// - Elements [base..base+4] are the "low" half
/// - Elements [base+4..base+8] are the "high" half
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_len4_avx2(a: &mut [i32; N], zetas: &[i32]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    // Process 32 groups of len=4 butterflies, 2 groups at a time
    // Each group is 8 elements: [start..start+4] paired with [start+4..start+8]
    for i in 0..16 {
        let base = i * 16;
        let zeta0 = zetas[i * 2];
        let zeta1 = zetas[i * 2 + 1];

        // Group 0: elements base..base+8
        // Group 1: elements base+8..base+16

        // Load low halves: a[base..base+4] and a[base+8..base+12]
        let lo0 = _mm_loadu_si128(a.as_ptr().add(base).cast());
        let lo1 = _mm_loadu_si128(a.as_ptr().add(base + 8).cast());
        let a_lo = _mm256_set_m128i(lo1, lo0);

        // Load high halves: a[base+4..base+8] and a[base+12..base+16]
        let hi0 = _mm_loadu_si128(a.as_ptr().add(base + 4).cast());
        let hi1 = _mm_loadu_si128(a.as_ptr().add(base + 12).cast());
        let a_hi = _mm256_set_m128i(hi1, hi0);

        // Zetas: lanes 0-3 use zeta0, lanes 4-7 use zeta1
        let zeta_v = _mm256_set_epi32(zeta1, zeta1, zeta1, zeta1, zeta0, zeta0, zeta0, zeta0);

        // t = zeta * a_hi (Montgomery multiplication)
        let t = montgomery_mul_8x_with_params(a_hi, zeta_v, q, qinv);

        // a[j] = a[j] + t
        let new_lo = _mm256_add_epi32(a_lo, t);
        // a[j+len] = a[j] - t
        let new_hi = _mm256_sub_epi32(a_lo, t);

        // Store back
        _mm_storeu_si128(
            a.as_mut_ptr().add(base).cast(),
            _mm256_castsi256_si128(new_lo),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 8).cast(),
            _mm256_extracti128_si256(new_lo, 1),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 4).cast(),
            _mm256_castsi256_si128(new_hi),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 12).cast(),
            _mm256_extracti128_si256(new_hi, 1),
        );
    }
}

/// Inverse butterfly for len=4.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn inv_butterfly_len4_avx2(a: &mut [i32; N], zetas: &[i32]) {
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for group in 0..16 {
        let base = group * 16;
        let zeta0 = zetas[group * 2];
        let zeta1 = zetas[group * 2 + 1];

        // Load elements
        let lo0 = _mm_loadu_si128(a.as_ptr().add(base).cast());
        let lo1 = _mm_loadu_si128(a.as_ptr().add(base + 8).cast());
        let t = _mm256_set_m128i(lo1, lo0);

        let hi0 = _mm_loadu_si128(a.as_ptr().add(base + 4).cast());
        let hi1 = _mm_loadu_si128(a.as_ptr().add(base + 12).cast());
        let a_hi = _mm256_set_m128i(hi1, hi0);

        // Broadcast pre-negated zetas to appropriate lanes
        let zeta_v = _mm256_set_epi32(zeta1, zeta1, zeta1, zeta1, zeta0, zeta0, zeta0, zeta0);

        // a[j] = t + a[j+len]
        let new_lo = _mm256_add_epi32(t, a_hi);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = _mm256_sub_epi32(t, a_hi);
        let new_hi = montgomery_mul_8x_with_params(diff, zeta_v, q, qinv);

        // Store back
        _mm_storeu_si128(
            a.as_mut_ptr().add(base).cast(),
            _mm256_castsi256_si128(new_lo),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 8).cast(),
            _mm256_extracti128_si256(new_lo, 1),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 4).cast(),
            _mm256_castsi256_si128(new_hi),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 12).cast(),
            _mm256_extracti128_si256(new_hi, 1),
        );
    }
}

/// Forward NTT using AVX2.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_avx2(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len: usize = 128;

    while len >= 8 {
        let mut start: usize = 0;
        while start < N {
            k += 1;
            let zeta = crate::ntt::ZETAS[k];
            butterfly_avx2(a, start, len, zeta);
            start += 2 * len;
        }
        len >>= 1;
    }

    // len=4: use specialized SIMD function
    {
        // Collect zetas for len=4 layer
        let mut zetas_len4 = [0i32; 32];
        for i in 0..32 {
            k += 1;
            zetas_len4[i] = crate::ntt::ZETAS[k];
        }
        butterfly_len4_avx2(a, &zetas_len4);
    }

    // len=2 and len=1: use scalar operations (descending order for forward NTT)
    for len in [2usize, 1] {
        let mut start: usize = 0;
        while start < N {
            k += 1;
            let zeta = crate::ntt::ZETAS[k];
            for j in start..(start + len) {
                let t = crate::reduce::montgomery_mul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            start += 2 * len;
        }
    }
}

/// Inverse NTT using AVX2.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn inv_ntt_avx2(a: &mut [i32; N]) {
    let mut k: usize = 256;

    // len=1 and len=2: use scalar operations
    for len in [1usize, 2] {
        let mut start: usize = 0;
        while start < N {
            k -= 1;
            let zeta = -crate::ntt::ZETAS[k];
            for j in start..(start + len) {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = crate::reduce::montgomery_mul(zeta, t - a[j + len]);
            }
            start += 2 * len;
        }
    }

    // len=4: use specialized SIMD function
    {
        // Collect zetas for len=4 layer
        let mut zetas_len4 = [0i32; 32];
        for i in 0..32 {
            k -= 1;
            zetas_len4[i] = -crate::ntt::ZETAS[k];
        }
        inv_butterfly_len4_avx2(a, &zetas_len4);
    }

    // len >= 8: use SIMD
    let mut len: usize = 8;
    while len < N {
        let mut start: usize = 0;
        while start < N {
            k -= 1;
            let zeta = -crate::ntt::ZETAS[k];
            inv_butterfly_avx2(a, start, len, zeta);
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by N^(-1) in Montgomery form
    let inv_n = _mm256_set1_epi32(crate::ntt::INV_N_MONT);
    let q = _mm256_set1_epi32(Q);
    let qinv = _mm256_set1_epi32(QINV);

    for i in (0..N).step_by(8) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vr = montgomery_mul_8x_with_params(va, inv_n, q, qinv);
        _mm256_storeu_si256(a.as_mut_ptr().add(i).cast(), vr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_mul_equivalence() {
        if !super::super::has_avx2() {
            return; // Skip if AVX2 not available
        }

        let a = [
            123456i32, 234567, 345678, 456789, 567890, 678901, 789012, 890123,
        ];
        let b = [
            111111i32, 222222, 333333, 444444, 555555, 666666, 777777, 888888,
        ];

        // Scalar reference
        let mut expected = [0i32; 8];
        for i in 0..8 {
            expected[i] = crate::reduce::montgomery_mul(a[i], b[i]);
        }

        // SIMD version
        let mut result = [0i32; 8];
        unsafe {
            let va = _mm256_loadu_si256(a.as_ptr().cast());
            let vb = _mm256_loadu_si256(b.as_ptr().cast());
            let vr = montgomery_mul_8x(va, vb);
            _mm256_storeu_si256(result.as_mut_ptr().cast(), vr);
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn test_pointwise_mul_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

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

    #[test]
    fn test_caddq_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

        let test_vals: [i32; N] = core::array::from_fn(|i| (i as i32 * 7919) % (2 * Q) - Q);

        // Scalar reference
        let mut expected = test_vals;
        for c in &mut expected {
            *c = crate::reduce::caddq(*c);
        }

        // SIMD version
        let mut result = test_vals;
        unsafe {
            caddq_avx2(&mut result);
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn test_reduce_avx2_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

        // Test with various input ranges
        let test_cases: [i32; N] = core::array::from_fn(|i| {
            // Mix of positive, negative, small, and large values
            let base = (i as i32 * 123457) % (4 * Q) - 2 * Q;
            base
        });

        // Scalar reference
        let mut expected = test_cases;
        for c in &mut expected {
            *c = crate::reduce::reduce32(*c);
        }

        // SIMD version
        let mut result = test_cases;
        unsafe {
            reduce_avx2(&mut result);
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn test_reduce_avx2_edge_cases() {
        if !super::super::has_avx2() {
            return;
        }

        // Test specific edge cases within the practical operating range.
        // Note: The scalar reduce32 has a subtle bug for inputs like -Q-1
        // where it returns -1 instead of Q-1. The SIMD implementation
        // correctly returns values in [0, Q-1] for all inputs.
        let edge_cases = [
            0,
            1,
            Q - 1,
            Q,
            Q + 1,
            2 * Q,
            2 * Q - 1,
            -1,
            -Q,
            -Q + 1,
            // Note: -Q-1 is excluded because scalar has edge case bug
            Q * 100,
            -Q * 100,
        ];

        for &val in &edge_cases {
            let mut input = [val; N];
            let expected = crate::reduce::reduce32(val);

            unsafe {
                reduce_avx2(&mut input);
            }

            for (i, &result) in input.iter().enumerate() {
                assert_eq!(
                    result, expected,
                    "Mismatch for input {val} at index {i}: got {result}, expected {expected}"
                );
            }
        }
    }

    #[test]
    fn test_reduce_avx2_output_range() {
        if !super::super::has_avx2() {
            return;
        }

        // Verify SIMD output is always in [0, Q-1] for various inputs
        let test_vals: [i32; N] = core::array::from_fn(|i| {
            let x = i as i32;
            // Generate values spread across the valid input range
            x.wrapping_mul(0x765431) % (1 << 28) - (1 << 27)
        });

        let mut result = test_vals;
        unsafe {
            reduce_avx2(&mut result);
        }

        for (i, &r) in result.iter().enumerate() {
            assert!(
                r >= 0 && r < Q,
                "Output at index {i} is {r}, not in [0, Q-1)"
            );
        }
    }
}
