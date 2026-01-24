//! SIMD optimizations for ML-DSA
//!
//! This module provides platform-specific SIMD implementations for
//! performance-critical operations while maintaining constant-time properties.
//!
//! # Supported Platforms
//!
//! - **x86_64**: AVX2 (256-bit, 8x i32)
//! - **aarch64**: NEON (128-bit, 4x i32)
//! - **wasm32**: SIMD128 (128-bit, 4x i32)
//!
//! # Safety
//!
//! This module contains unsafe code for SIMD intrinsics. All functions
//! are marked with appropriate `#[target_feature]` attributes and safety
//! documentation.

#![allow(unsafe_code)]

use crate::poly::N;

// Platform-specific implementations
#[cfg(target_arch = "x86_64")]
mod avx2;

#[cfg(target_arch = "aarch64")]
mod neon;

#[cfg(target_arch = "wasm32")]
mod wasm;

// ============================================================================
// Safe wrapper functions
// ============================================================================

/// Check if AVX2 is available at runtime (x86_64 only).
///
/// On x86_64, this uses CPUID to detect AVX2 support.
/// On other architectures, this always returns false.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn has_avx2() -> bool {
    // Compile-time detection: if AVX2 is enabled at compile time, always return true
    #[cfg(target_feature = "avx2")]
    {
        true
    }
    #[cfg(not(target_feature = "avx2"))]
    {
        // Runtime detection (the macro caches internally)
        #[cfg(feature = "std")]
        {
            std::arch::is_x86_feature_detected!("avx2")
        }
        #[cfg(not(feature = "std"))]
        {
            false
        }
    }
}

/// Check if NEON is available (aarch64).
///
/// NEON is always available on aarch64, so this returns true.
#[cfg(target_arch = "aarch64")]
#[inline]
#[allow(dead_code)]
pub const fn has_neon() -> bool {
    true
}

/// Check if SIMD128 is available (wasm32).
///
/// Returns true if compiled with simd128 target feature.
#[cfg(target_arch = "wasm32")]
#[inline]
pub const fn has_simd128() -> bool {
    cfg!(target_feature = "simd128")
}

// ============================================================================
// Safe public API - wraps unsafe SIMD intrinsics
// ============================================================================

/// Pointwise multiplication using SIMD (AVX2).
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::pointwise_mul(r, a, b);
        }
        true
    } else {
        false
    }
}

/// Pointwise multiply-accumulate using SIMD (AVX2).
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::pointwise_mul_acc(r, a, b);
        }
        true
    } else {
        false
    }
}

/// Pointwise multiplication using SIMD (NEON).
///
/// Returns true if SIMD was used.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::pointwise_mul(r, a, b);
    }
    true
}

/// Pointwise multiply-accumulate using SIMD (NEON).
///
/// Returns true if SIMD was used.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::pointwise_mul_acc(r, a, b);
    }
    true
}

/// Pointwise multiplication using SIMD (WASM SIMD128).
///
/// Returns true if SIMD was used.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline]
pub fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    // SAFETY: simd128 confirmed via target_feature
    unsafe {
        wasm::pointwise_mul(r, a, b);
    }
    true
}

/// Pointwise multiply-accumulate using SIMD (WASM SIMD128).
///
/// Returns true if SIMD was used.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline]
pub fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool {
    // SAFETY: simd128 confirmed via target_feature
    unsafe {
        wasm::pointwise_mul_acc(r, a, b);
    }
    true
}

/// Fallback for unsupported architectures.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
#[inline]
pub fn pointwise_mul(_r: &mut [i32; N], _a: &[i32; N], _b: &[i32; N]) -> bool {
    false
}

/// Fallback for unsupported architectures.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
#[inline]
pub fn pointwise_mul_acc(_r: &mut [i32; N], _a: &[i32; N], _b: &[i32; N]) -> bool {
    false
}

// ============================================================================
// NTT SIMD API
// ============================================================================

/// Forward NTT using SIMD (AVX2).
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn ntt(a: &mut [i32; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::ntt_avx2(a);
        }
        true
    } else {
        false
    }
}

/// Inverse NTT using SIMD (AVX2).
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inv_ntt(a: &mut [i32; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::inv_ntt_avx2(a);
        }
        true
    } else {
        false
    }
}

/// Forward NTT using SIMD (NEON).
///
/// Returns true if SIMD was used.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn ntt(a: &mut [i32; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::ntt_neon(a);
    }
    true
}

/// Inverse NTT using SIMD (NEON).
///
/// Returns true if SIMD was used.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn inv_ntt(a: &mut [i32; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::inv_ntt_neon(a);
    }
    true
}

/// Forward NTT fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn ntt(_a: &mut [i32; N]) -> bool {
    false
}

/// Inverse NTT fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn inv_ntt(_a: &mut [i32; N]) -> bool {
    false
}
