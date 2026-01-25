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
// Use explicit a = a + b form for consistency with ntt.rs scalar implementation
#![allow(clippy::assign_op_pattern)]
// Allow dead_code for poly_add/poly_sub which are implemented but not yet
// integrated into the main poly.rs. These will be used in a future PR to
// accelerate polynomial arithmetic throughout the crate.
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::ntt::ZETAS;
use crate::params::common::N;
use crate::reduce::INV_N_MONT;

/// ML-KEM modulus q = 3329
const Q: i16 = 3329;

/// Q inverse mod 2^16: q^(-1) mod 2^16 = -3327
const QINV: i16 = -3327i16;

/// Barrett constant V: floor(2^26 / q + 0.5) = 20159
/// This fits in i16 (20159 < 32768)
const BARRETT_V: i16 = 20159;

// ============================================================================
// Core reduction operations for 16-bit coefficients
// ============================================================================

/// Efficient Barrett reduction on 16 values in parallel (16-bit only).
///
/// Uses the pqcrystals/kyber approach: only 16-bit SIMD operations.
/// Pattern: vpmulhw -> vpsraw -> vpmullw -> vpsubw
///
/// For input a in range [-2^15, 2^15], computes a mod q.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn barrett_reduce_16x(a: __m256i) -> __m256i {
    let v = _mm256_set1_epi16(BARRETT_V);
    let q = _mm256_set1_epi16(Q);

    // t = (a * v) >> 16 (high 16 bits of signed multiply)
    let t = _mm256_mulhi_epi16(a, v);

    // t = t >> 10 (total shift: >> 26, since mulhi already gives >> 16)
    let t = _mm256_srai_epi16(t, 10);

    // t = t * q (low 16 bits)
    let t = _mm256_mullo_epi16(t, q);

    // result = a - t
    _mm256_sub_epi16(a, t)
}

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
    let ab_lo = _mm256_mullo_epi16(a, b); // Low 16 bits of each product
    let ab_hi = _mm256_mulhi_epi16(a, b); // High 16 bits (signed)

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

    // Scalar fallback. For ML-KEM's NTT usage, len is always a power of 2 >= 16,
    // so the SIMD loop above processes all elements and this loop is not entered.
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

        // a[j] = barrett_reduce(t + a[j+len]) to prevent overflow
        let sum = _mm256_add_epi16(t, a_hi);
        let new_lo = barrett_reduce_16x(sum);

        // a[j+len] = (t - a[j+len]) * zeta
        let diff = _mm256_sub_epi16(t, a_hi);
        let new_hi = montgomery_mul_16x(zeta_v, diff, q, qinv);

        _mm256_storeu_si256(a.as_mut_ptr().add(j).cast(), new_lo);
        _mm256_storeu_si256(a.as_mut_ptr().add(j + len).cast(), new_hi);

        j += 16;
    }

    // Scalar fallback. For ML-KEM's NTT usage, len is always a power of 2 >= 16,
    // so the SIMD loop above processes all elements and this loop is not entered.
    while j < start + len {
        let t = a[j];
        a[j] = crate::reduce::barrett_reduce(t.wrapping_add(a[j + len]));
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
        let zeta_v = _mm256_set_m128i(_mm_set1_epi16(zeta1), _mm_set1_epi16(zeta0));

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
        let zeta_v = _mm256_set_m128i(_mm_set1_epi16(zeta1), _mm_set1_epi16(zeta0));

        // a[j] = barrett_reduce(t + a[j+len]) to prevent overflow
        let sum = _mm256_add_epi16(t, a_hi);
        let new_lo = barrett_reduce_16x(sum);

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
        let zetas_len8: [i16; 16] = ZETAS[k..k + 16].try_into().unwrap();
        k += 16;
        butterfly_len8_avx2(a, &zetas_len8);
    }

    // len=4, 2: use scalar operations (SIMD not efficient for small lengths)
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
        let zetas_len8: [i16; 16] = core::array::from_fn(|i| -ZETAS[k - i]);
        k = k.wrapping_sub(16);
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
// Basemul SIMD operations
// ============================================================================

/// Accumulate polynomial basemul: r += a * b in NTT domain using AVX2.
///
/// Processes 16 coefficients (4 coefficient groups, 8 basemul operations) per iteration.
///
/// Each group of 4 coefficients has 2 basemul pairs:
/// - basemul([a0,a1], [b0,b1], +zeta) -> [r0, r1]
/// - basemul([a2,a3], [b2,b3], -zeta) -> [r2, r3]
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_basemul_acc_avx2(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    let q = _mm256_set1_epi16(Q);
    let qinv = _mm256_set1_epi16(QINV);

    // Process 16 coefficients (4 groups) per iteration
    // 256 coefficients / 16 = 16 iterations
    for i in 0..16 {
        let base = i * 16;
        // ZETAS[64..128] contain the precomputed twiddle factors for basemul.
        // The NTT uses ZETAS[0..64] for butterfly operations, while basemul
        // uses ZETAS[64..128] for the polynomial ring structure (X^2 - zeta).
        let zeta_idx = 64 + i * 4;

        // Load 16 coefficients from a, b, and r
        let va = _mm256_loadu_si256(a.as_ptr().add(base).cast());
        let vb = _mm256_loadu_si256(b.as_ptr().add(base).cast());
        let vr = _mm256_loadu_si256(r.as_ptr().add(base).cast());

        // Prepare zeta vector: [z0, z0, -z0, -z0, z1, z1, -z1, -z1, z2, z2, -z2, -z2, z3, z3, -z3, -z3]
        // Each group uses +zeta for first pair, -zeta for second pair
        let z0 = ZETAS[zeta_idx];
        let z1 = ZETAS[zeta_idx + 1];
        let z2 = ZETAS[zeta_idx + 2];
        let z3 = ZETAS[zeta_idx + 3];
        let zeta_v = _mm256_setr_epi16(
            z0, z0, -z0, -z0, z1, z1, -z1, -z1, z2, z2, -z2, -z2, z3, z3, -z3, -z3,
        );

        // Compute basemul for all 8 pairs
        let result = basemul_8x(va, vb, zeta_v, q, qinv);

        // Accumulate: r += result
        let vr_new = _mm256_add_epi16(vr, result);
        _mm256_storeu_si256(r.as_mut_ptr().add(base).cast(), vr_new);
    }
}

/// Compute 8 basemul operations in parallel.
///
/// Input layout: [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15]
/// Each pair (a[2i], a[2i+1]) is a 2-coefficient input for basemul.
///
/// Basemul formula for pair (a0, a1) * (b0, b1) with zeta:
///   r0 = a0*b0 + a1*b1*zeta
///   r1 = a0*b1 + a1*b0
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn basemul_8x(a: __m256i, b: __m256i, zeta: __m256i, q: __m256i, qinv: __m256i) -> __m256i {
    // Extract even indices: [a0, a2, a4, a6, a8, a10, a12, a14]
    // Extract odd indices:  [a1, a3, a5, a7, a9, a11, a13, a15]
    let a_even = shuffle_even_16(a);
    let a_odd = shuffle_odd_16(a);
    let b_even = shuffle_even_16(b);
    let b_odd = shuffle_odd_16(b);

    // Extract even zetas (for r_even = a_even*b_even + a_odd*b_odd*zeta)
    let zeta_even = shuffle_even_16(zeta);

    // r_even = a_even*b_even + a_odd*b_odd*zeta
    let t1 = montgomery_mul_16x(a_even, b_even, q, qinv);
    let t2 = montgomery_mul_16x(a_odd, b_odd, q, qinv);
    let t3 = montgomery_mul_16x(t2, zeta_even, q, qinv);
    let r_even = _mm256_add_epi16(t1, t3);

    // r_odd = a_even*b_odd + a_odd*b_even
    let t4 = montgomery_mul_16x(a_even, b_odd, q, qinv);
    let t5 = montgomery_mul_16x(a_odd, b_even, q, qinv);
    let r_odd = _mm256_add_epi16(t4, t5);

    // Interleave back: [r0, r1, r2, r3, ...]
    interleave_16(r_even, r_odd)
}

/// Extract even-indexed i16 values: [a0, a2, a4, ...] from [a0, a1, a2, a3, ...]
///
/// Uses byte shuffle to extract even i16 elements from each 128-bit lane,
/// then combines them into a single 128-bit result broadcast to both lanes.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn shuffle_even_16(a: __m256i) -> __m256i {
    // Shuffle bytes to move even i16s to lower 64 bits within each 128-bit lane.
    // Byte indices for even i16s (0, 2, 4, 6 in each lane):
    //   i16[0] = bytes 0-1, i16[2] = bytes 4-5, i16[4] = bytes 8-9, i16[6] = bytes 12-13
    // The -1 values zero out the upper 64 bits (not used).
    let shuffle_mask = _mm256_setr_epi8(
        0, 1, 4, 5, 8, 9, 12, 13, // Lane 0: extract even i16s to low 64 bits
        -1, -1, -1, -1, -1, -1, -1, -1, // Lane 0: zero upper 64 bits
        0, 1, 4, 5, 8, 9, 12, 13, // Lane 1: same pattern
        -1, -1, -1, -1, -1, -1, -1, -1, // Lane 1: zero upper 64 bits
    );
    let shuffled = _mm256_shuffle_epi8(a, shuffle_mask);

    // Extract the low 64 bits from each 128-bit lane
    let lo_lane0 = _mm256_castsi256_si128(shuffled);
    let lo_lane1 = _mm256_extracti128_si256(shuffled, 1);

    // Combine into one 128-bit register: [lane0_even_4, lane1_even_4]
    let combined = _mm_unpacklo_epi64(lo_lane0, lo_lane1);

    // Broadcast to both 128-bit lanes of 256-bit register.
    //
    // Note: We intentionally broadcast rather than zero-extend because this
    // function's callers may read from either lane. If zero-extension were
    // needed, use `_mm256_zextsi128_si256` (stable since Rust 1.27.0) instead
    // of `_mm256_castsi128_si256` (whose upper bits are undefined per Intel spec).
    _mm256_set_m128i(combined, combined)
}

/// Extract odd-indexed i16 values: [a1, a3, a5, ...] from [a0, a1, a2, a3, ...]
///
/// Uses byte shuffle to extract odd i16 elements from each 128-bit lane,
/// then combines them into a single 128-bit result broadcast to both lanes.
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn shuffle_odd_16(a: __m256i) -> __m256i {
    // Shuffle bytes to move odd i16s to lower 64 bits within each 128-bit lane.
    // Byte indices for odd i16s (1, 3, 5, 7 in each lane):
    //   i16[1] = bytes 2-3, i16[3] = bytes 6-7, i16[5] = bytes 10-11, i16[7] = bytes 14-15
    // The -1 values zero out the upper 64 bits (not used).
    let shuffle_mask = _mm256_setr_epi8(
        2, 3, 6, 7, 10, 11, 14, 15, // Lane 0: extract odd i16s to low 64 bits
        -1, -1, -1, -1, -1, -1, -1, -1, // Lane 0: zero upper 64 bits
        2, 3, 6, 7, 10, 11, 14, 15, // Lane 1: same pattern
        -1, -1, -1, -1, -1, -1, -1, -1, // Lane 1: zero upper 64 bits
    );
    let shuffled = _mm256_shuffle_epi8(a, shuffle_mask);

    // Extract the low 64 bits from each 128-bit lane
    let lo_lane0 = _mm256_castsi256_si128(shuffled);
    let lo_lane1 = _mm256_extracti128_si256(shuffled, 1);

    // Combine into one 128-bit register: [lane0_odd_4, lane1_odd_4]
    let combined = _mm_unpacklo_epi64(lo_lane0, lo_lane1);

    // Broadcast to both 128-bit lanes of 256-bit register.
    //
    // Note: We intentionally broadcast rather than zero-extend because this
    // function's callers may read from either lane. If zero-extension were
    // needed, use `_mm256_zextsi128_si256` (stable since Rust 1.27.0) instead
    // of `_mm256_castsi128_si256` (whose upper bits are undefined per Intel spec).
    _mm256_set_m128i(combined, combined)
}

/// Interleave even and odd values: [e0, o0, e1, o1, e2, o2, ...]
///
/// Input:  even = [e0, e1, e2, e3, e4, e5, e6, e7, ...]
///         odd  = [o0, o1, o2, o3, o4, o5, o6, o7, ...]
/// Output: [e0, o0, e1, o1, e2, o2, e3, o3, e4, o4, e5, o5, e6, o6, e7, o7]
///
/// # Safety
///
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn interleave_16(even: __m256i, odd: __m256i) -> __m256i {
    // even and odd are in lower 128 bits only (from shuffle_even/odd)
    let even_128 = _mm256_castsi256_si128(even);
    let odd_128 = _mm256_castsi256_si128(odd);

    // Unpack low: interleave first 4 pairs
    let lo = _mm_unpacklo_epi16(even_128, odd_128);
    // Unpack high: interleave last 4 pairs
    let hi = _mm_unpackhi_epi16(even_128, odd_128);

    // Combine into 256-bit register
    _mm256_set_m128i(hi, lo)
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
            123, 234, 345, 456, 567, 678, 789, 890, 901, 1012, 1123, 1234, 1345, 1456, 1567, 1678,
        ];
        let b: [i16; 16] = [
            111, 222, 333, 444, 555, 666, 777, 888, 999, 1110, 1221, 1332, 1443, 1554, 1665, 1776,
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

        // Scalar NTT (call scalar function directly to avoid SIMD dispatch)
        let mut poly_wrapper = crate::poly::Poly::from_coeffs(poly_scalar);
        crate::ntt::ntt_scalar(&mut poly_wrapper);
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

        // Scalar inverse NTT (call scalar function directly to avoid SIMD dispatch)
        let mut poly_wrapper = crate::poly::Poly::from_coeffs(poly_scalar);
        crate::ntt::inv_ntt_scalar(&mut poly_wrapper);
        poly_scalar = poly_wrapper.coeffs;

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
        if !super::super::has_avx2() {
            return;
        }

        // Create test polynomial
        let mut poly = [0i16; N];
        for (i, coeff) in poly.iter_mut().enumerate() {
            *coeff = ((i * 13 + 7) % 3329) as i16;
        }
        let original = poly;

        // Forward NTT then inverse NTT
        unsafe {
            ntt_avx2(&mut poly);
            inv_ntt_avx2(&mut poly);
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

    #[test]
    fn test_poly_basemul_acc_simd_equivalence() {
        if !super::super::has_avx2() {
            return;
        }

        // Create test polynomials in NTT domain
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        for i in 0..N {
            a[i] = ((i * 17 + 31) % 3329) as i16;
            b[i] = ((i * 23 + 47) % 3329) as i16;
        }

        // SIMD version
        let mut r_simd = [0i16; N];
        unsafe {
            poly_basemul_acc_avx2(&mut r_simd, &a, &b);
        }

        // Scalar version
        let mut r_scalar = [0i16; N];
        let a_poly = crate::poly::Poly::from_coeffs(a);
        let b_poly = crate::poly::Poly::from_coeffs(b);
        let mut r_poly = crate::poly::Poly::from_coeffs(r_scalar);
        crate::poly::poly_basemul_acc_scalar(&mut r_poly, &a_poly, &b_poly);
        r_scalar = r_poly.coeffs;

        // Compare mod Q (values may differ by multiples of q)
        for i in 0..N {
            let simd_val = crate::reduce::barrett_reduce_full(r_simd[i]);
            let scalar_val = crate::reduce::barrett_reduce_full(r_scalar[i]);
            assert_eq!(
                simd_val, scalar_val,
                "poly_basemul_acc SIMD vs scalar mismatch at index {}: {} vs {}",
                i, r_simd[i], r_scalar[i]
            );
        }
    }
}
