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

// Generate has_avx2() / has_neon() detection functions
kylix_core::define_has_avx2!();

/// Check if SIMD128 is available (wasm32).
///
/// Returns true if compiled with simd128 target feature.
#[cfg(target_arch = "wasm32")]
#[inline]
pub const fn has_simd128() -> bool {
    cfg!(target_feature = "simd128")
}

// Pointwise multiplication dispatch (Pattern B: avx2 + neon + wasm)
kylix_core::define_simd_dispatch! {
    pub fn pointwise_mul(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool;
    avx2: avx2::pointwise_mul(r, a, b),
    neon: neon::pointwise_mul(r, a, b),
    wasm: wasm::pointwise_mul(r, a, b)
}

kylix_core::define_simd_dispatch! {
    pub fn pointwise_mul_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) -> bool;
    avx2: avx2::pointwise_mul_acc(r, a, b),
    neon: neon::pointwise_mul_acc(r, a, b),
    wasm: wasm::pointwise_mul_acc(r, a, b)
}

// NTT dispatch (Pattern A: avx2 + neon)
kylix_core::define_simd_dispatch! {
    pub fn ntt(a: &mut [i32; N]) -> bool;
    avx2: avx2::ntt_avx2(a),
    neon: neon::ntt_neon(a)
}

kylix_core::define_simd_dispatch! {
    pub fn inv_ntt(a: &mut [i32; N]) -> bool;
    avx2: avx2::inv_ntt_avx2(a),
    neon: neon::inv_ntt_neon(a)
}

// Barrett reduction dispatch (Pattern C: avx2 only)
kylix_core::define_simd_dispatch! {
    pub fn reduce(a: &mut [i32; N]) -> bool;
    avx2: avx2::reduce_avx2(a)
}

kylix_core::define_simd_dispatch! {
    pub fn caddq(a: &mut [i32; N]) -> bool;
    avx2: avx2::caddq_avx2(a)
}
