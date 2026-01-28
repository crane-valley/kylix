//! Modular arithmetic macros for lattice-based cryptography.
//!
//! This module provides macros to generate modular arithmetic operations
//! (Barrett reduction, Montgomery reduction) for different parameter sets.
//!
//! Both ML-KEM and ML-DSA use similar algorithms but with different
//! coefficient types (i16 vs i32) and moduli.

/// Generate Barrett reduction function (approximate).
///
/// Barrett reduction computes `a mod q` without division using precomputed constants.
/// This version produces approximate results that may be in range [0, 2q-1].
///
/// # Parameters
/// - `$name`: Function name (e.g., `barrett_reduce`)
/// - `$coeff`: Coefficient type (i16 or i32)
/// - `$wide`: Wide type for intermediate computations (i32 or i64)
/// - `$q`: The prime modulus
/// - `$barrett_mul`: Precomputed constant ≈ 2^k / q
/// - `$shift`: Bit shift amount (k), typically 26 for i16, 48 for i32
#[macro_export]
macro_rules! define_barrett_reduce {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        wide: $wide:ty,
        q: $q:expr,
        barrett_mul: $barrett_mul:expr,
        shift: $shift:expr
    ) => {
        /// Barrett reduction: compute approximate a mod q without division.
        /// Result may be in range [0, 2q-1] for positive inputs.
        #[inline]
        pub const fn $name(a: $coeff) -> $coeff {
            let a = a as $wide;
            let t = ((a * $barrett_mul) >> $shift) as $coeff;
            (a - (t as $wide) * ($q as $wide)) as $coeff
        }
    };
}

/// Generate Barrett reduction function with rounding (for ML-KEM style).
///
/// This version adds half before shifting for better accuracy.
#[macro_export]
macro_rules! define_barrett_reduce_rounded {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        wide: $wide:ty,
        q: $q:expr,
        barrett_mul: $barrett_mul:expr,
        shift: $shift:expr
    ) => {
        /// Barrett reduction with rounding: compute a mod q without division.
        #[inline]
        pub const fn $name(a: $coeff) -> $coeff {
            let a = a as $wide;
            let half = 1 as $wide << ($shift - 1);
            let t = ((a * $barrett_mul + half) >> $shift) as $coeff;
            (a - (t as $wide) * ($q as $wide)) as $coeff
        }
    };
}

/// Generate Montgomery reduction function.
///
/// Montgomery reduction computes `a * R^(-1) mod q` where R is a power of 2.
///
/// # Parameters
/// - `$name`: Function name (e.g., `montgomery_reduce`)
/// - `$coeff`: Coefficient type (i16 or i32)
/// - `$wide`: Wide type for input (i32 or i64)
/// - `$q`: The prime modulus
/// - `$qinv`: q^(-1) mod R (as signed integer for wrapping mul)
/// - `$shift`: Bit shift amount (log2(R)), typically 16 for i16, 32 for i32
#[macro_export]
macro_rules! define_montgomery_reduce {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        wide: $wide:ty,
        q: $q:expr,
        qinv: $qinv:expr,
        shift: $shift:expr
    ) => {
        /// Montgomery reduction: compute a * R^(-1) mod q.
        #[inline]
        pub const fn $name(a: $wide) -> $coeff {
            // t = (a mod R) * qinv mod R
            let t = (a as $coeff).wrapping_mul($qinv as $coeff);
            // (a - t*q) / R
            ((a - (t as $wide) * ($q as $wide)) >> $shift) as $coeff
        }
    };
}

/// Generate Montgomery multiplication function.
///
/// Computes `a * b * R^(-1) mod q` for values in Montgomery form.
#[macro_export]
macro_rules! define_montgomery_mul {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        wide: $wide:ty,
        montgomery_reduce: $mont_reduce:ident
    ) => {
        /// Montgomery multiplication: compute a * b * R^(-1) mod q.
        #[inline]
        pub const fn $name(a: $coeff, b: $coeff) -> $coeff {
            $mont_reduce((a as $wide) * (b as $wide))
        }
    };
}

/// Generate conditional add of q (for centering reduction).
///
/// Adds q if the input is negative, used to ensure non-negative results.
#[macro_export]
macro_rules! define_caddq {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        q: $q:expr
    ) => {
        /// Conditional add q: add q if a is negative.
        #[inline]
        pub const fn $name(a: $coeff) -> $coeff {
            // mask is -1 (all 1s) if a < 0, else 0
            let mask = a >> (core::mem::size_of::<$coeff>() * 8 - 1);
            a + ($q & mask)
        }
    };
}

/// Generate freeze function (reduce to canonical [0, q-1]).
#[macro_export]
macro_rules! define_freeze {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        q: $q:expr,
        reduce_approx: $reduce_approx:ident
    ) => {
        /// Freeze: reduce to canonical [0, q-1] range.
        #[inline]
        pub const fn $name(a: $coeff) -> $coeff {
            let r = $reduce_approx(a);
            let r = r - $q;
            let mask = r >> (core::mem::size_of::<$coeff>() * 8 - 1);
            r + ($q & mask)
        }
    };
}

#[cfg(test)]
mod tests {
    // Basic tests for the macros
    define_barrett_reduce! {
        name: test_barrett,
        coeff: i32,
        wide: i64,
        q: 8380417,
        barrett_mul: 33_556_102i64,
        shift: 48
    }

    define_montgomery_reduce! {
        name: test_montgomery,
        coeff: i32,
        wide: i64,
        q: 8380417,
        qinv: 58_728_449i32,
        shift: 32
    }

    define_caddq! {
        name: test_caddq,
        coeff: i32,
        q: 8380417
    }

    #[test]
    fn test_barrett_basic() {
        // Note: Barrett reduction is approximate, result may be in [0, 2q-1]
        assert_eq!(test_barrett(0), 0);
        // For a = q, result may be 0 or q depending on constants
        let r = test_barrett(8380417);
        assert!(r == 0 || r == 8380417, "Barrett(q) should be 0 or q, got {}", r);
        // For a = q + 1, result should be 1 or q + 1
        let r = test_barrett(8380418);
        assert!(r == 1 || r == 8380418, "Barrett(q+1) should be 1 or q+1, got {}", r);
    }

    #[test]
    fn test_caddq_basic() {
        assert_eq!(test_caddq(0), 0);
        assert_eq!(test_caddq(100), 100);
        assert_eq!(test_caddq(-1), 8380416);
        assert_eq!(test_caddq(-100), 8380317);
    }
}
