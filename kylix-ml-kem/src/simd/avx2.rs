//! AVX2 SIMD optimizations for ML-KEM (x86_64)
//!
//! This module provides AVX2-accelerated implementations of performance-critical
//! operations. All operations maintain constant-time properties.
//!
//! # Performance
//!
//! AVX2 provides 256-bit registers, allowing:
//! - 16x i16 operations in parallel (ML-KEM's coefficient size)
//!
//! This is 2x more parallelism than ML-DSA's 32-bit coefficients.
//!
//! # Safety
//!
//! All functions require AVX2 support. Use `super::has_avx2()` to check availability.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::ntt::ZETAS;
use crate::reduce::INV_N_MONT;
use crate::params::common::N;

/// ML-KEM modulus q = 3329
const Q: i16 = 3329;

/// Q inverse mod 2^16: q^(-1) mod 2^16 = -3327
const QINV: i16 = -3327i16;

// ============================================================================
// Core Montgomery operations for 16-bit coefficients
// ============================================================================

/// Montgomery multiplication on 16 values in parallel.
///
/// Computes r = a * b * R^(-1) mod q for 16 coefficient pairs where R = 2^16.
///
/// # Algorithm
///
/// For 16-bit Montgomery multiplication:
/// 1. ab_lo = (a * b) mod 2^16   (low 16 bits)
/// 2. ab_hi = (a * b) >> 16      (high 16 bits, signed)
/// 3. t = ab_lo * QINV mod 2^16
/// 4. tq_hi = (t * q) >> 16      (high 16 bits, signed)
/// 5. result = ab_hi - tq_hi
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn montgomery_mul_16x(a: __m256i, b: __m256i, q: __m256i, qinv: __m256i) -> __m256i {
    // Step 1-2: Compute a * b, get low and high 16 bits
    let ab_lo = _mm256_mullo_epi16(a, b);  // Low 16 bits of each product
    let ab_hi = _mm256_mulhi_epi16(a, b);  // High 16 bits (signed)

    // Step 3: t = ab_lo * QINV mod 2^16
    let t = _mm256_mullo_epi16(ab_lo, qinv);

    // Step 4: tq_hi = (t * q) >> 16
    let tq_hi = _mm256_mulhi_epi16(t, q);

    // Step 5: result = ab_hi - tq_hi
    _mm256_sub_epi16(ab_hi, tq_hi)
}

// ============================================================================
// Butterfly operations
// ============================================================================

/// Forward NTT butterfly for len >= 16.
///
/// Processes 16 coefficient pairs at a time:
///   t = zeta * a[j + len]       (Montgomery multiplication)
///   a[j + len] = a[j] - t
///   a[j] = a[j] + t
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(a: &mut [i16; N], start: usize, len: usize, zeta: i16) {
    let zeta_v = _mm256_set1_epi16(zeta);
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    let mut j = start;
    while j + 16 <= start + len {
        let a_lo = _mm256_loadu_si256(a.as_ptr().add(j).cast());
        let a_hi = _mm256_loadu_si256(a.as_ptr().add(j + len).cast());

        // t = zeta * a[j + len] (Montgomery multiplication)
        let t = montgomery_mul_16x(zeta_v, a_hi, q, qinv);

        // a[j] = a[j] + t
        let new_lo = _mm256_add_epi16(a_lo, t);
        // a[j+len] = a[j] - t
        let new_hi = _mm256_sub_epi16(a_lo, t);

        _mm256_storeu_si256(a.as_mut_ptr().add(j).cast(), new_lo);
        _mm256_storeu_si256(a.as_mut_ptr().add(j + len).cast(), new_hi);

        j += 16;
    }

    // Handle remaining elements with scalar (when len < 16)
    while j < start + len {
        let t = crate::reduce::montgomery_mul(zeta, a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
        j += 1;
    }
}

/// Inverse NTT butterfly for len >= 16.
///
/// Processes 16 coefficient pairs at a time:
///   t = a[j]
///   a[j] = t + a[j + len]
///   a[j + len] = (t - a[j + len]) * zeta (Montgomery multiplication)
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn inv_butterfly_avx2(a: &mut [i16; N], start: usize, len: usize, zeta: i16) {
    let zeta_v = _mm256_set1_epi16(zeta);
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    let mut j = start;
    while j + 16 <= start + len {
        let t = _mm256_loadu_si256(a.as_ptr().add(j).cast());
        let a_hi = _mm256_loadu_si256(a.as_ptr().add(j + len).cast());

        // a[j] = t + a[j+len]
        let new_lo = _mm256_add_epi16(t, a_hi);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = _mm256_sub_epi16(t, a_hi);
        let new_hi = montgomery_mul_16x(zeta_v, diff, q, qinv);

        _mm256_storeu_si256(a.as_mut_ptr().add(j).cast(), new_lo);
        _mm256_storeu_si256(a.as_mut_ptr().add(j + len).cast(), new_hi);

        j += 16;
    }

    // Handle remaining elements with scalar
    while j < start + len {
        let t = a[j];
        a[j] = t.wrapping_add(a[j + len]);
        a[j + len] = crate::reduce::montgomery_mul(zeta, t.wrapping_sub(a[j + len]));
        j += 1;
    }
}

/// Butterfly for len=8: process using half-vector operations.
///
/// For len=8, we have pairs of 8 elements, so we use 128-bit halves.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_len8_avx2(a: &mut [i16; N], zetas: &[i16]) {
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    // Process 16 groups of len=8 butterflies, 2 groups at a time
    for i in 0..8 {
        let base = i * 32;
        let zeta0 = zetas[i * 2];
        let zeta1 = zetas[i * 2 + 1];

        // Group 0: elements base..base+16
        // Group 1: elements base+16..base+32

        // Load low halves: a[base..base+8] and a[base+16..base+24]
        let lo0 = _mm_loadu_si128(a.as_ptr().add(base).cast());
        let lo1 = _mm_loadu_si128(a.as_ptr().add(base + 16).cast());
        let a_lo = _mm256_set_m128i(lo1, lo0);

        // Load high halves: a[base+8..base+16] and a[base+24..base+32]
        let hi0 = _mm_loadu_si128(a.as_ptr().add(base + 8).cast());
        let hi1 = _mm_loadu_si128(a.as_ptr().add(base + 24).cast());
        let a_hi = _mm256_set_m128i(hi1, hi0);

        // Zetas: low 8 lanes use zeta0, high 8 lanes use zeta1
        let zeta_v = _mm256_set_m128i(
            _mm_set1_epi16(zeta1),
            _mm_set1_epi16(zeta0),
        );

        // t = zeta * a_hi (Montgomery multiplication)
        let t = montgomery_mul_16x(zeta_v, a_hi, q, qinv);

        // a[j] = a[j] + t
        let new_lo = _mm256_add_epi16(a_lo, t);
        // a[j+len] = a[j] - t
        let new_hi = _mm256_sub_epi16(a_lo, t);

        // Store back
        _mm_storeu_si128(
            a.as_mut_ptr().add(base).cast(),
            _mm256_castsi256_si128(new_lo),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 16).cast(),
            _mm256_extracti128_si256(new_lo, 1),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 8).cast(),
            _mm256_castsi256_si128(new_hi),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 24).cast(),
            _mm256_extracti128_si256(new_hi, 1),
        );
    }
}

/// Inverse butterfly for len=8.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn inv_butterfly_len8_avx2(a: &mut [i16; N], zetas: &[i16]) {
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    for i in 0..8 {
        let base = i * 32;
        let zeta0 = zetas[i * 2];
        let zeta1 = zetas[i * 2 + 1];

        // Load elements
        let lo0 = _mm_loadu_si128(a.as_ptr().add(base).cast());
        let lo1 = _mm_loadu_si128(a.as_ptr().add(base + 16).cast());
        let t = _mm256_set_m128i(lo1, lo0);

        let hi0 = _mm_loadu_si128(a.as_ptr().add(base + 8).cast());
        let hi1 = _mm_loadu_si128(a.as_ptr().add(base + 24).cast());
        let a_hi = _mm256_set_m128i(hi1, hi0);

        // Zetas (already negated by caller)
        let zeta_v = _mm256_set_m128i(
            _mm_set1_epi16(zeta1),
            _mm_set1_epi16(zeta0),
        );

        // a[j] = t + a[j+len]
        let new_lo = _mm256_add_epi16(t, a_hi);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = _mm256_sub_epi16(t, a_hi);
        let new_hi = montgomery_mul_16x(zeta_v, diff, q, qinv);

        // Store back
        _mm_storeu_si128(
            a.as_mut_ptr().add(base).cast(),
            _mm256_castsi256_si128(new_lo),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 16).cast(),
            _mm256_extracti128_si256(new_lo, 1),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 8).cast(),
            _mm256_castsi256_si128(new_hi),
        );
        _mm_storeu_si128(
            a.as_mut_ptr().add(base + 24).cast(),
            _mm256_extracti128_si256(new_hi, 1),
        );
    }
}

// ============================================================================
// NTT implementations
// ============================================================================

/// Forward NTT using AVX2.
///
/// Transforms polynomial from coefficient representation to NTT domain.
/// Uses Cooley-Tukey butterfly with decimation-in-time.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_avx2(a: &mut [i16; N]) {
    let mut k: usize = 1;
    let mut len: usize = 128;

    // len >= 16: use full SIMD
    while len >= 16 {
        let mut start: usize = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            butterfly_avx2(a, start, len, zeta);
            start += 2 * len;
        }
        len >>= 1;
    }

    // len=8: use specialized half-vector operations
    {
        let mut zetas_len8 = [0i16; 16];
        for i in 0..16 {
            zetas_len8[i] = ZETAS[k];
            k += 1;
        }
        butterfly_len8_avx2(a, &zetas_len8);
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

/// Inverse NTT using AVX2.
///
/// Transforms polynomial from NTT domain back to coefficient representation.
/// Uses Gentleman-Sande butterfly with decimation-in-frequency.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn inv_ntt_avx2(a: &mut [i16; N]) {
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

    // len=8: use specialized half-vector operations
    {
        let mut zetas_len8 = [0i16; 16];
        for i in 0..16 {
            zetas_len8[i] = -ZETAS[k];
            k = k.wrapping_sub(1);
        }
        inv_butterfly_len8_avx2(a, &zetas_len8);
    }

    // len >= 16: use full SIMD
    let mut len: usize = 16;
    while len <= 128 {
        let mut start: usize = 0;
        while start < N {
            let zeta = -ZETAS[k];
            k = k.wrapping_sub(1);
            inv_butterfly_avx2(a, start, len, zeta);
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by N^(-1) in Montgomery form using SIMD
    let inv_n = _mm256_set1_epi16(INV_N_MONT);
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    for i in (0..N).step_by(16) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vr = montgomery_mul_16x(inv_n, va, q, qinv);
        _mm256_storeu_si256(a.as_mut_ptr().add(i).cast(), vr);
    }
}

// ============================================================================
// Polynomial arithmetic
// ============================================================================

/// Polynomial addition using AVX2.
///
/// Computes r[i] = a[i] + b[i] for all 256 coefficients.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in (0..N).step_by(16) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());

        let vr = _mm256_add_epi16(va, vb);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr);
    }
}

/// Polynomial subtraction using AVX2.
///
/// Computes r[i] = a[i] - b[i] for all 256 coefficients.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in (0..N).step_by(16) {
        let va = _mm256_loadu_si256(a.as_ptr().add(i).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast());

        let vr = _mm256_sub_epi16(va, vb);

        _mm256_storeu_si256(r.as_mut_ptr().add(i).cast(), vr);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_mul_16x_equivalence() {
        if !super::super::has_avx2() {
            return; // Skip if AVX2 not available
        }

        let a: [i16; 16] = [
            123, 234, 345, 456, 567, 678, 789, 890,
            901, 1012, 1123, 1234, 1345, 1456, 1567, 1678,
        ];
        let b: [i16; 16] = [
            111, 222, 333, 444, 555, 666, 777, 888,
            999, 1110, 1221, 1332, 1443, 1554, 1665, 1776,
        ];

        // Scalar reference
        let mut expected = [0i16; 16];
        for i in 0..16 {
            expected[i] = crate::reduce::montgomery_mul(a[i], b[i]);
        }

        // SIMD version
        let mut result = [0i16; 16];
        unsafe {
            let va = _mm256_loadu_si256(a.as_ptr().cast());
            let vb = _mm256_loadu_si256(b.as_ptr().cast());
            let q = _mm256_set1_epi16(Q);
            let qinv = _mm256_set1_epi16(QINV);
            let vr = montgomery_mul_16x(va, vb, q, qinv);
            _mm256_storeu_si256(result.as_mut_ptr().cast(), vr);
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn test_ntt_simd_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

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
            ntt_avx2(&mut poly_simd);
        }

        // Scalar NTT
        let mut poly_wrapper = crate::poly::Poly::from_coeffs(poly_scalar);
        crate::ntt::ntt(&mut poly_wrapper);
        poly_scalar = poly_wrapper.coeffs;

        assert_eq!(poly_simd, poly_scalar, "NTT SIMD vs scalar mismatch");
    }

    #[test]
    fn test_inv_ntt_simd_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

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
            inv_ntt_avx2(&mut poly_simd);
        }

        // Scalar inverse NTT
        let mut poly_wrapper = crate::poly::Poly::from_coeffs(poly_scalar);
        crate::ntt::inv_ntt(&mut poly_wrapper);
        poly_scalar = poly_wrapper.coeffs;

        assert_eq!(poly_simd, poly_scalar, "INVNTT SIMD vs scalar mismatch");
    }

    #[test]
    fn test_ntt_roundtrip() {
        if !super::super::has_avx2() {
            return;
        }

        // Create test polynomial
        let mut poly = [0i16; N];
        for i in 0..N {
            poly[i] = ((i * 13 + 7) % 3329) as i16;
        }
        let original = poly;

        // Forward NTT then inverse NTT
        unsafe {
            ntt_avx2(&mut poly);
            inv_ntt_avx2(&mut poly);
        }

        // Result should match original (after from_mont conversion)
        for i in 0..N {
            let result = crate::reduce::barrett_reduce_full(crate::reduce::from_mont(poly[i]));
            let expected = crate::reduce::barrett_reduce_full(original[i]);
            assert_eq!(result, expected, "Roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn test_poly_add_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = (i as i16) % 3329;
            b[i] = ((i * 2) as i16) % 3329;
        }

        // Scalar reference
        let mut expected = [0i16; N];
        for i in 0..N {
            expected[i] = a[i].wrapping_add(b[i]);
        }

        // SIMD version
        let mut result = [0i16; N];
        unsafe {
            poly_add(&mut result, &a, &b);
        }

        assert_eq!(expected, result);
    }

    #[test]
    fn test_poly_sub_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = ((i + 100) as i16) % 3329;
            b[i] = (i as i16) % 3329;
        }

        // Scalar reference
        let mut expected = [0i16; N];
        for i in 0..N {
            expected[i] = a[i].wrapping_sub(b[i]);
        }

        // SIMD version
        let mut result = [0i16; N];
        unsafe {
            poly_sub(&mut result, &a, &b);
        }

        assert_eq!(expected, result);
    }
}
