//! SIMD dispatch macros for lattice-based cryptography.
//!
//! This module provides macros to generate platform-specific SIMD dispatch
//! functions. Both ML-KEM and ML-DSA use the same dispatch pattern
//! (AVX2/NEON/WASM with scalar fallback) but with different function
//! signatures and backend implementations.

/// Generate platform detection functions for SIMD dispatch.
///
/// Generates:
/// - `has_avx2() -> bool` on x86_64 (compile-time fast path + runtime detection)
/// - `has_neon() -> bool` on aarch64 (always true)
///
/// # Example
///
/// ```ignore
/// kylix_core::define_has_avx2!();
/// // Now has_avx2() and has_neon() are available in this scope
/// ```
#[macro_export]
macro_rules! define_has_avx2 {
    () => {
        /// Check if AVX2 is available at runtime (x86_64 only).
        #[cfg(target_arch = "x86_64")]
        #[inline]
        pub fn has_avx2() -> bool {
            #[cfg(target_feature = "avx2")]
            {
                true
            }
            #[cfg(not(target_feature = "avx2"))]
            {
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
    };
}

/// Generate a SIMD dispatch function that tries platform-specific
/// implementations and returns `bool` indicating whether SIMD was used.
///
/// Three dispatch patterns are supported, selected by which platform
/// keywords are provided:
///
/// - **Pattern A** (`avx2` + `neon`): 2-arch dispatch with scalar fallback
/// - **Pattern B** (`avx2` + `neon` + `wasm`): 3-arch dispatch with scalar fallback
/// - **Pattern C** (`avx2` only): AVX2-only dispatch with scalar fallback
///
/// # Example
///
/// ```ignore
/// // Pattern A: avx2 + neon
/// kylix_core::define_simd_dispatch! {
///     pub fn ntt(poly: &mut Poly) -> bool;
///     avx2: avx2::ntt_avx2(&mut poly.coeffs),
///     neon: neon::ntt_neon(&mut poly.coeffs)
/// }
///
/// // Pattern C: avx2 only
/// kylix_core::define_simd_dispatch! {
///     pub fn reduce(a: &mut [i32; N]) -> bool;
///     avx2: avx2::reduce_avx2(a)
/// }
/// ```
#[macro_export]
macro_rules! define_simd_dispatch {
    // Pattern A: avx2 + neon + fallback
    (
        $(#[$attr:meta])*
        pub fn $name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> bool;
        avx2: $avx2_call:expr,
        neon: $neon_call:expr
    ) => {
        $(#[$attr])*
        #[cfg(target_arch = "x86_64")]
        pub fn $name( $($arg : $argty),* ) -> bool {
            if has_avx2() {
                unsafe { $avx2_call; }
                true
            } else {
                false
            }
        }

        $(#[$attr])*
        #[cfg(target_arch = "aarch64")]
        pub fn $name( $($arg : $argty),* ) -> bool {
            unsafe { $neon_call; }
            true
        }

        $(#[$attr])*
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        #[allow(unused_variables)]
        pub fn $name( $($arg : $argty),* ) -> bool {
            false
        }
    };

    // Pattern B: avx2 + neon + wasm + fallback
    (
        $(#[$attr:meta])*
        pub fn $name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> bool;
        avx2: $avx2_call:expr,
        neon: $neon_call:expr,
        wasm: $wasm_call:expr
    ) => {
        $(#[$attr])*
        #[cfg(target_arch = "x86_64")]
        pub fn $name( $($arg : $argty),* ) -> bool {
            if has_avx2() {
                unsafe { $avx2_call; }
                true
            } else {
                false
            }
        }

        $(#[$attr])*
        #[cfg(target_arch = "aarch64")]
        pub fn $name( $($arg : $argty),* ) -> bool {
            unsafe { $neon_call; }
            true
        }

        $(#[$attr])*
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        pub fn $name( $($arg : $argty),* ) -> bool {
            unsafe { $wasm_call; }
            true
        }

        $(#[$attr])*
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            all(target_arch = "wasm32", target_feature = "simd128")
        )))]
        #[allow(unused_variables)]
        pub fn $name( $($arg : $argty),* ) -> bool {
            false
        }
    };

    // Pattern C: avx2-only + fallback
    (
        $(#[$attr:meta])*
        pub fn $name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> bool;
        avx2: $avx2_call:expr
    ) => {
        $(#[$attr])*
        #[cfg(target_arch = "x86_64")]
        pub fn $name( $($arg : $argty),* ) -> bool {
            if has_avx2() {
                unsafe { $avx2_call; }
                true
            } else {
                false
            }
        }

        $(#[$attr])*
        #[cfg(not(target_arch = "x86_64"))]
        #[allow(unused_variables)]
        pub fn $name( $($arg : $argty),* ) -> bool {
            false
        }
    };
}
