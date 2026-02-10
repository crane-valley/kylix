//! NTT (Number Theoretic Transform) macros for lattice-based cryptography.
//!
//! This module provides macros to generate forward and inverse NTT functions
//! for different parameter sets. Both ML-KEM and ML-DSA use the same
//! algorithmic structure (Cooley-Tukey forward, Gentleman-Sande inverse)
//! but with different coefficient types, moduli, and butterfly details.

/// Generate a forward NTT function (Cooley-Tukey, decimation-in-time).
///
/// The forward NTT transforms a polynomial from coefficient representation
/// to NTT domain (evaluations at roots of unity).
///
/// # Parameters
/// - `$name`: Function name (e.g., `ntt_scalar`)
/// - `$coeff`: Coefficient type (`i16` or `i32`)
/// - `$n`: Polynomial degree (typically 256)
/// - `$len_min`: Minimum butterfly length (ML-KEM: 2, ML-DSA: 1)
/// - `$zetas`: Zeta table constant (twiddle factors in Montgomery form)
/// - `$mont_mul`: Montgomery multiplication function
///
/// # Generated function
/// `pub(crate) fn $name(coeffs: &mut [$coeff; $n])`
///
/// The zeta table is accessed starting at index 1 with read-then-increment.
/// This unifies ML-KEM (k=1, post-increment) and ML-DSA (k=0, pre-increment)
/// patterns, since both access ZETAS\[1\], ZETAS\[2\], ... in the same order.
#[macro_export]
macro_rules! define_ntt_forward {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        n: $n:expr,
        len_min: $len_min:expr,
        zetas: $zetas:expr,
        montgomery_mul: $mont_mul:ident
    ) => {
        /// Forward NTT: Cooley-Tukey butterfly (decimation-in-time).
        pub(crate) fn $name(coeffs: &mut [$coeff; $n]) {
            let mut k: usize = 1;
            let mut len: usize = $n / 2;

            while len >= $len_min {
                let mut start: usize = 0;
                while start < $n {
                    let zeta = $zetas[k];
                    k += 1;

                    for j in start..(start + len) {
                        let t = $mont_mul(zeta, coeffs[j + len]);
                        let u = coeffs[j];
                        coeffs[j] = u + t;
                        coeffs[j + len] = u - t;
                    }
                    start += 2 * len;
                }
                len >>= 1;
            }
        }
    };
}

/// Generate an inverse NTT function (Gentleman-Sande, decimation-in-frequency).
///
/// The inverse NTT transforms from NTT domain back to coefficient representation,
/// with final scaling by N^(-1) in Montgomery form.
///
/// # Parameters
/// - `$name`: Function name (e.g., `inv_ntt_scalar`)
/// - `$coeff`: Coefficient type (`i16` or `i32`)
/// - `$n`: Polynomial degree (typically 256)
/// - `$k_start`: Initial zeta index value (e.g., ML-KEM: `n/2` = 128, ML-DSA: `n` = 256)
/// - `$len_start`: Initial butterfly length (ML-KEM: 2, ML-DSA: 1)
/// - `$zetas`: Zeta table constant
/// - `$mont_mul`: Montgomery multiplication function
/// - `$inv_n_mont`: N^(-1) in Montgomery form for final scaling
/// - `$sum_fn`: Function for butterfly sum: `fn($coeff, $coeff) -> $coeff`
/// - `$diff_fn`: Function for butterfly difference: `fn($coeff, $coeff) -> $coeff`
///
/// # Generated function
/// `pub(crate) fn $name(coeffs: &mut [$coeff; $n])`
///
/// The butterfly uses `$sum_fn(t, x)` for the sum branch and
/// `montgomery_mul(neg_zeta, $diff_fn(t, x))` for the difference branch.
/// This allows ML-KEM to apply Barrett reduction on the sum and use
/// wrapping arithmetic, while ML-DSA uses plain addition/subtraction.
///
/// Zeta indexing uses pre-decrement from `$k_start`, accessing
/// `ZETAS[$k_start - 1]` first. The negation `-ZETAS[k]` is applied
/// inside the macro to unify ML-KEM (`-zeta`) and ML-DSA (`-ZETAS[k]`).
#[macro_export]
macro_rules! define_ntt_inverse {
    (
        name: $name:ident,
        coeff: $coeff:ty,
        n: $n:expr,
        k_start: $k_start:expr,
        len_start: $len_start:expr,
        zetas: $zetas:expr,
        montgomery_mul: $mont_mul:ident,
        inv_n_mont: $inv_n_mont:expr,
        butterfly_sum: $sum_fn:ident,
        butterfly_diff: $diff_fn:ident
    ) => {
        /// Inverse NTT: Gentleman-Sande butterfly (decimation-in-frequency).
        pub(crate) fn $name(coeffs: &mut [$coeff; $n]) {
            let mut k: usize = $k_start;
            let mut len: usize = $len_start;

            while len <= $n / 2 {
                let mut start: usize = 0;
                while start < $n {
                    k -= 1;
                    let neg_zeta = -$zetas[k];

                    for j in start..(start + len) {
                        let t = coeffs[j];
                        let x = coeffs[j + len];
                        coeffs[j] = $sum_fn(t, x);
                        coeffs[j + len] = $mont_mul(neg_zeta, $diff_fn(t, x));
                    }
                    start += 2 * len;
                }
                len <<= 1;
            }

            // Final scaling by N^(-1) in Montgomery form
            for c in coeffs.iter_mut() {
                *c = $mont_mul(*c, $inv_n_mont);
            }
        }
    };
}

#[cfg(test)]
mod tests {
    // Test with ML-KEM-like parameters (i16, q=3329)
    mod kem_like {
        const Q: i16 = 3329;
        const QINV: i32 = -3327;
        const BARRETT_MUL: i32 = 20159;

        crate::define_barrett_reduce_rounded! {
            name: barrett_reduce,
            coeff: i16,
            wide: i32,
            q: Q,
            barrett_mul: BARRETT_MUL,
            shift: 26
        }

        crate::define_montgomery_reduce! {
            name: montgomery_reduce,
            coeff: i16,
            wide: i32,
            q: Q,
            qinv: QINV,
            shift: 16
        }

        crate::define_montgomery_mul! {
            name: montgomery_mul,
            coeff: i16,
            wide: i32,
            montgomery_reduce: montgomery_reduce
        }

        // INV_N_MONT = 256^(-1) * 2^16 mod q = 1441
        const INV_N_MONT: i16 = 1441;

        // Full ML-KEM zeta table for 256-element NTT roundtrip testing.
        // zetas[0] is unused by the forward NTT (which starts at k=1).
        const ZETAS: [i16; 128] = [
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855,
            1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411,
            3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711,
            2167, 126, 1469, 2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604,
            448, 2264, 677, 2054, 2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094,
            3038, 2869, 1574, 1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457,
            349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
            1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459, 478, 3221,
            3021, 996, 991, 958, 1869, 1522, 1628,
        ];

        // Forward NTT (len_min=2 for ML-KEM style)
        define_ntt_forward! {
            name: ntt_scalar,
            coeff: i16,
            n: 256,
            len_min: 2,
            zetas: ZETAS,
            montgomery_mul: montgomery_mul
        }

        // Inverse NTT helpers
        #[inline]
        fn inv_ntt_sum(t: i16, x: i16) -> i16 {
            barrett_reduce(t.wrapping_add(x))
        }

        #[inline]
        fn inv_ntt_diff(t: i16, x: i16) -> i16 {
            t.wrapping_sub(x)
        }

        define_ntt_inverse! {
            name: inv_ntt_scalar,
            coeff: i16,
            n: 256,
            k_start: 256 / 2,
            len_start: 2,
            zetas: ZETAS,
            montgomery_mul: montgomery_mul,
            inv_n_mont: INV_N_MONT,
            butterfly_sum: inv_ntt_sum,
            butterfly_diff: inv_ntt_diff
        }

        // Reduce to canonical [0, q-1] using constant-time freeze
        crate::define_freeze! {
            name: full_reduce,
            coeff: i16,
            q: Q,
            reduce_approx: barrett_reduce
        }

        /// Convert from Montgomery form
        fn from_mont(a: i16) -> i16 {
            montgomery_reduce(a as i32)
        }

        #[test]
        fn test_ntt_zero() {
            let mut coeffs = [0i16; 256];
            ntt_scalar(&mut coeffs);
            for (i, &c) in coeffs.iter().enumerate() {
                assert_eq!(c, 0, "NTT of zero should be zero at index {}", i);
            }
        }

        #[test]
        fn test_ntt_roundtrip() {
            let mut coeffs = [0i16; 256];
            for (i, c) in coeffs.iter_mut().enumerate() {
                *c = (i as i16) % Q;
            }
            let original: [i16; 256] = coeffs; // by-value copy before mutation

            ntt_scalar(&mut coeffs);
            inv_ntt_scalar(&mut coeffs);

            for (i, (&got_raw, &expected_raw)) in coeffs.iter().zip(original.iter()).enumerate() {
                let got = full_reduce(from_mont(got_raw));
                let expected = full_reduce(expected_raw);
                assert_eq!(got, expected, "roundtrip failed at index {}", i);
            }
        }

        #[test]
        fn test_ntt_modifies_input() {
            let mut coeffs = [1i16; 256];
            ntt_scalar(&mut coeffs);
            let unchanged = coeffs.iter().filter(|&&c| c == 1).count();
            assert!(
                unchanged < 256,
                "NTT should modify at least some coefficients"
            );
        }
    }

    // Test with ML-DSA-like parameters (i32, q=8380417)
    mod dsa_like {
        const Q: i32 = 8_380_417;
        const QINV: i32 = 58_728_449;
        const INV_N_MONT: i32 = 41978;

        crate::define_montgomery_reduce! {
            name: montgomery_reduce,
            coeff: i32,
            wide: i64,
            q: Q,
            qinv: QINV,
            shift: 32
        }

        crate::define_montgomery_mul! {
            name: montgomery_mul,
            coeff: i32,
            wide: i64,
            montgomery_reduce: montgomery_reduce
        }

        crate::define_caddq! {
            name: caddq,
            coeff: i32,
            q: Q
        }

        /// Reduce from Montgomery form to canonical [0, q-1] (constant-time).
        fn full_reduce(a: i32) -> i32 {
            let r = caddq(a);
            // Constant-time conditional subtract: if r >= q then r - q, else r
            let r = r - Q;
            const SIGN_BIT: u32 = (core::mem::size_of::<i32>() * 8 - 1) as u32;
            r + (Q & (r >> SIGN_BIT))
        }

        // First 256 ML-DSA zetas (from FIPS 204 reference)
        #[rustfmt::skip]
        const ZETAS: [i32; 256] = [
                 0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
           1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
           2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
          -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
           2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
          -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
          -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
            811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
          -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
          -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
           3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
           -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
          -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
          -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
            189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
           1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
           2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
            266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
            900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
           -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
            342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
           2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
          -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
          -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
          -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
           -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
          -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
          -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
          -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
           -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
          -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
           -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782,
        ];

        // Forward NTT (len_min=1 for ML-DSA style)
        define_ntt_forward! {
            name: ntt_scalar,
            coeff: i32,
            n: 256,
            len_min: 1,
            zetas: ZETAS,
            montgomery_mul: montgomery_mul
        }

        // Inverse NTT helpers
        #[inline]
        fn inv_ntt_sum(t: i32, x: i32) -> i32 {
            t + x
        }

        #[inline]
        fn inv_ntt_diff(t: i32, x: i32) -> i32 {
            t - x
        }

        define_ntt_inverse! {
            name: inv_ntt_scalar,
            coeff: i32,
            n: 256,
            k_start: 256,
            len_start: 1,
            zetas: ZETAS,
            montgomery_mul: montgomery_mul,
            inv_n_mont: INV_N_MONT,
            butterfly_sum: inv_ntt_sum,
            butterfly_diff: inv_ntt_diff
        }

        #[test]
        fn test_ntt_zero() {
            let mut coeffs = [0i32; 256];
            ntt_scalar(&mut coeffs);
            for (i, &c) in coeffs.iter().enumerate() {
                assert_eq!(c, 0, "NTT of zero should be zero at index {}", i);
            }
        }

        #[test]
        fn test_ntt_roundtrip() {
            let mut coeffs = [0i32; 256];
            coeffs[0] = 100;
            coeffs[1] = 200;
            coeffs[100] = 12345;
            let original = coeffs;

            ntt_scalar(&mut coeffs);
            inv_ntt_scalar(&mut coeffs);

            for (i, (&c, &expected)) in coeffs.iter().zip(original.iter()).enumerate() {
                let got = full_reduce(montgomery_reduce(c as i64));
                assert_eq!(got, expected, "roundtrip failed at index {}", i);
            }
        }

        #[test]
        fn test_ntt_modifies_input() {
            let mut coeffs = [0i32; 256];
            coeffs[0] = 1;
            let original = coeffs;
            ntt_scalar(&mut coeffs);
            assert_ne!(coeffs, original, "NTT should modify coefficients");
        }
    }
}
