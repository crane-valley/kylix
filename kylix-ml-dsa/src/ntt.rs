//! Number Theoretic Transform for ML-DSA
//!
//! 9-layer NTT for q = 8380417 with complete factorization.
//! The primitive 512th root of unity is ζ = 1753.

use crate::poly::N;
use crate::reduce::{montgomery_mul, montgomery_reduce};

/// Primitive 512th root of unity modulo q.
/// ζ = 1753, with ζ^512 ≡ 1 (mod q) and ζ^256 ≡ -1 (mod q).
pub const ZETA: i32 = 1753;

/// Scaling factor for inverse NTT: R^2 * N^(-1) mod q
/// This produces output in Montgomery form (scaled by R).
/// N^(-1) mod q = 8347681, R^2 mod q = 2365951
/// INV_N_MONT = 2365951 * 8347681 mod 8380417 = 41978
pub const INV_N_MONT: i32 = 41978;

/// Precomputed powers of zeta in Montgomery form for forward NTT.
/// zetas[i] = ζ^(brv(i)) * R mod q where brv is bit-reversal and R = 2^32.
/// Values from the FIPS 204 / Dilithium reference implementation (pq-crystals/dilithium).
/// Note: zetas[0] is unused since the NTT loop uses ++k before access.
#[rustfmt::skip]
pub const ZETAS: [i32; 256] = [
    // zetas[0] = 0 is intentionally unused; NTT loop uses pre-increment before access
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

/// Forward NTT: polynomial to NTT domain.
///
/// Input: polynomial with coefficients in standard form
/// Output: polynomial in NTT domain (evaluations at roots of unity)
pub fn ntt(a: &mut [i32; N]) {
    // Try SIMD implementation first
    #[cfg(feature = "simd")]
    {
        if crate::simd::ntt(a) {
            return;
        }
    }

    // Scalar fallback
    ntt_scalar(a);
}

/// Scalar implementation of forward NTT.
#[inline]
fn ntt_scalar(a: &mut [i32; N]) {
    let mut k: usize = 0;
    let mut len: usize = 128;

    while len >= 1 {
        let mut start: usize = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];

            for j in start..(start + len) {
                let t = montgomery_mul(zeta, a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT: NTT domain to polynomial (Montgomery form output).
///
/// Input: polynomial in NTT domain
/// Output: polynomial with coefficients in Montgomery form (scaled by R)
///
/// Includes the 1/N normalization and R factor via INV_N_MONT multiplication.
/// To convert to standard form, apply from_mont() to each coefficient.
pub fn inv_ntt(a: &mut [i32; N]) {
    // Try SIMD implementation first
    #[cfg(feature = "simd")]
    {
        if crate::simd::inv_ntt(a) {
            return;
        }
    }

    // Scalar fallback
    inv_ntt_scalar(a);
}

/// Scalar implementation of inverse NTT.
#[inline]
fn inv_ntt_scalar(a: &mut [i32; N]) {
    let mut k: usize = 256;
    let mut len: usize = 1;

    while len < N {
        let mut start: usize = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];

            for j in start..(start + len) {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_mul(zeta, a[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by N^(-1) in Montgomery form to get proper inverse NTT
    for c in a.iter_mut() {
        *c = montgomery_mul(*c, INV_N_MONT);
    }
}

/// Compute the product of two polynomials in NTT domain.
/// Result is accumulated into r: r += a * b (pointwise).
///
/// Correctly applies Montgomery reduction only to the product,
/// then adds to the accumulator.
pub fn pointwise_acc(r: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    // Try SIMD optimized path
    #[cfg(feature = "simd")]
    {
        if crate::simd::pointwise_mul_acc(r, a, b) {
            return;
        }
    }

    // Scalar fallback
    for i in 0..N {
        // Montgomery reduce the product, then add to accumulator
        r[i] += montgomery_reduce((a[i] as i64) * (b[i] as i64));
    }
}

/// Initialize zetas table at runtime (for verification).
/// This computes ζ^(brv(i)) * R mod q.
#[cfg(test)]
fn compute_zetas() -> [i32; 256] {
    use crate::reduce::{to_mont, Q};

    let mut zetas = [0i32; 256];

    // Compute powers of zeta in bit-reversed order
    fn bit_reverse(mut x: usize, bits: usize) -> usize {
        let mut result = 0;
        for _ in 0..bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }

    // zetas[0] = R (Montgomery representation of 1)
    zetas[0] = to_mont(1);

    // Compute ζ^1, ζ^2, ..., ζ^255 and store in bit-reversed order
    let mut power = 1i64;
    for i in 1..256 {
        power = (power * (ZETA as i64)) % (Q as i64);
        let brv_i = bit_reverse(i, 8);
        zetas[brv_i] = to_mont(power as i32);
    }

    zetas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reduce::{caddq, montgomery_reduce, Q};

    #[test]
    fn test_pointwise_then_invntt() {
        // Test that inv_ntt(A ⊙ B) = (a * b) where ⊙ is Montgomery pointwise mul
        // and * is negacyclic convolution

        // Create simple polynomials
        let mut a = [0i32; N];
        let mut b = [0i32; N];
        a[0] = 1; // a = 1
        b[0] = 1; // b = 1
                  // So a * b = 1 (convolution of two constants)

        // NTT
        ntt(&mut a);
        ntt(&mut b);

        // Pointwise Montgomery multiply
        let mut c = [0i32; N];
        for i in 0..N {
            c[i] = crate::reduce::montgomery_mul(a[i], b[i]);
        }

        // inv_NTT
        inv_ntt(&mut c);

        // c should now be (a * b) = 1, possibly scaled
        // Since a = b = 1, the convolution a * b = 1 * 1 = 1 (scalar multiplication)
        // But we had Montgomery mul in NTT domain, so there's scaling

        // The result should be: inv_ntt(a_hat ⊙ b_hat) = (a * b) where the R's cancel
        // Let's check
        eprintln!("a_orig = [1, 0, 0, ...]");
        eprintln!("b_orig = [1, 0, 0, ...]");
        eprintln!("Expected a*b = [1, 0, 0, ...]");
        eprintln!("Actual c[0..4] = {:?}", &c[0..4]);

        // With caddq for normalization
        for i in 0..N {
            c[i] = caddq(c[i]);
        }
        eprintln!("After caddq, c[0..4] = {:?}", &c[0..4]);

        // Check if c[0] = 1
        assert_eq!(c[0], 1, "inv_ntt of pointwise product of unit should be 1");
        for i in 1..N {
            assert_eq!(c[i], 0, "Other coefficients should be 0");
        }
    }

    #[test]
    fn test_ntt_inv_ntt_roundtrip() {
        // Test values - the Dilithium NTT operates on values in standard form
        // and the output of inv_ntt is in Montgomery form (multiplied by R)
        let mut a = [0i32; N];
        a[0] = 100;
        a[1] = 200;
        a[100] = 12345;

        // Save original
        let original = a;

        // Forward NTT: standard form -> NTT domain (still standard form internally)
        ntt(&mut a);

        // Inverse NTT: NTT domain -> Montgomery form (scaled by R)
        inv_ntt(&mut a);

        // The inverse NTT output is in Montgomery form.
        // Apply from_mont (montgomery_reduce) to get back to standard form.
        for i in 0..N {
            let val = montgomery_reduce(a[i] as i64);
            let got = caddq(val);
            let got = if got >= Q { got - Q } else { got };
            let expected = original[i];
            assert_eq!(
                got, expected,
                "Mismatch at index {i}: got {got}, expected {expected}"
            );
        }
    }

    #[test]
    fn test_zeta_properties() {
        // ζ^256 should be -1 mod q
        let mut power = 1i64;
        for _ in 0..256 {
            power = (power * (ZETA as i64)) % (Q as i64);
        }
        assert_eq!(power, (Q - 1) as i64, "ζ^256 should be -1 mod q");

        // ζ^512 should be 1 mod q
        power = 1;
        for _ in 0..512 {
            power = (power * (ZETA as i64)) % (Q as i64);
        }
        assert_eq!(power, 1, "ζ^512 should be 1 mod q");
    }
}
