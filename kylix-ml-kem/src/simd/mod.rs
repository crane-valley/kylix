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

// Generate has_avx2() / has_neon() detection functions
kylix_core::define_has_avx2!();

// NTT dispatch
kylix_core::define_simd_dispatch! {
    pub fn ntt(poly: &mut Poly) -> bool;
    avx2: avx2::ntt_avx2(&mut poly.coeffs),
    neon: neon::ntt_neon(&mut poly.coeffs)
}

kylix_core::define_simd_dispatch! {
    pub fn inv_ntt(poly: &mut Poly) -> bool;
    avx2: avx2::inv_ntt_avx2(&mut poly.coeffs),
    neon: neon::inv_ntt_neon(&mut poly.coeffs)
}

// Polynomial arithmetic dispatch
kylix_core::define_simd_dispatch! {
    #[allow(dead_code)]
    pub fn poly_add(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool;
    avx2: avx2::poly_add(r, a, b),
    neon: neon::poly_add(r, a, b)
}

kylix_core::define_simd_dispatch! {
    #[allow(dead_code)]
    pub fn poly_sub(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool;
    avx2: avx2::poly_sub(r, a, b),
    neon: neon::poly_sub(r, a, b)
}

// Basemul accumulate dispatch
kylix_core::define_simd_dispatch! {
    pub fn poly_basemul_acc(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) -> bool;
    avx2: avx2::poly_basemul_acc_avx2(r, a, b),
    neon: neon::poly_basemul_acc_neon(r, a, b)
}
