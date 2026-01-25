//! SIMD optimizations for ML-KEM
//!
//! This module provides platform-specific SIMD implementations for
//! performance-critical operations while maintaining constant-time properties.
//!
//! # Supported Platforms
//!
//! - **x86_64**: AVX2 (256-bit, 16x i16)
//! - **aarch64**: NEON (128-bit, 8x i16)
//!
//! # Key Advantage
//!
//! ML-KEM uses 16-bit coefficients (i16), allowing 16 parallel operations
//! per AVX2 instruction (vs 8 for ML-DSA's 32-bit coefficients).
//!
//! # Safety
//!
//! This module contains unsafe code for SIMD intrinsics. All functions
//! are marked with appropriate `#[target_feature]` attributes and safety
//! documentation.

#![allow(unsafe_code)]

use crate::params::common::N;
use crate::poly::Poly;

// Platform-specific implementations
#[cfg(target_arch = "x86_64")]
mod avx2;

#[cfg(target_arch = "aarch64")]
mod neon;

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

// ============================================================================
// NTT SIMD API
// ============================================================================

/// Forward NTT using SIMD (AVX2).
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn ntt(poly: &mut Poly) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::ntt_avx2(&mut poly.coeffs);
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
pub fn inv_ntt(poly: &mut Poly) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::inv_ntt_avx2(&mut poly.coeffs);
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
pub fn ntt(poly: &mut Poly) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::ntt_neon(&mut poly.coeffs);
    }
    true
}

/// Inverse NTT using SIMD (NEON).
///
/// Returns true if SIMD was used.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn inv_ntt(poly: &mut Poly) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::inv_ntt_neon(&mut poly.coeffs);
    }
    true
}

/// Forward NTT fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn ntt(_poly: &mut Poly) -> bool {
    false
}

/// Inverse NTT fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn inv_ntt(_poly: &mut Poly) -> bool {
    false
}

// ============================================================================
// Polynomial arithmetic SIMD API
// ============================================================================

/// Polynomial addition using SIMD.
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
#[allow(dead_code)]
pub fn poly_add(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::poly_add(r, a, b);
        }
        true
    } else {
        false
    }
}

/// Polynomial subtraction using SIMD.
///
/// Returns true if SIMD was used, false if caller should use scalar fallback.
#[cfg(target_arch = "x86_64")]
#[inline]
#[allow(dead_code)]
pub fn poly_sub(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool {
    if has_avx2() {
        // SAFETY: AVX2 availability confirmed by has_avx2()
        unsafe {
            avx2::poly_sub(r, a, b);
        }
        true
    } else {
        false
    }
}

/// Polynomial addition using SIMD (NEON).
#[cfg(target_arch = "aarch64")]
#[inline]
#[allow(dead_code)]
pub fn poly_add(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::poly_add(r, a, b);
    }
    true
}

/// Polynomial subtraction using SIMD (NEON).
#[cfg(target_arch = "aarch64")]
#[inline]
#[allow(dead_code)]
pub fn poly_sub(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool {
    // SAFETY: NEON is always available on aarch64
    unsafe {
        neon::poly_sub(r, a, b);
    }
    true
}

/// Fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn poly_add(_r: &mut [i16; N], _a: &[i16; N], _b: &[i16; N]) -> bool {
    false
}

/// Fallback for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn poly_sub(_r: &mut [i16; N], _a: &[i16; N], _b: &[i16; N]) -> bool {
    false
}
