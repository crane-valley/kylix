//! Core ML-DSA signing algorithms
//!
//! Implements KeyGen, Sign, Verify per FIPS 204.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::hash::{h, h2, hash_message, hash_pk, Shake128Xof};
use crate::packing::*;
use crate::poly::{Poly, N};
use crate::polyvec::{Matrix, PolyVecK, PolyVecL};
use crate::reduce::{freeze, Q};
use crate::rounding::{highbits, lowbits, make_hint, power2round, use_hint, D};
use crate::sample::{sample_eta, sample_in_ball, sample_mask, sample_ntt};

use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Validate hint encoding per FIPS 204 canonical requirements.
///
/// Checks that hint positions are within bounds, strictly increasing per
/// polynomial, and unused slots are zero. Returns total hint count if valid,
/// `None` if invalid.
fn validate_hints<const K: usize, const OMEGA: usize>(h: &[u8]) -> Option<usize> {
    if h.len() != OMEGA + K {
        return None;
    }

    let mut hint_count = 0;
    for i in 0..K {
        let start = if i == 0 { 0 } else { h[OMEGA + i - 1] as usize };
        let end = h[OMEGA + i] as usize;

        if end > OMEGA || end < start {
            return None;
        }

        let mut prev_pos: Option<u8> = None;
        for idx in start..end {
            let pos = h[idx];
            if pos as usize >= N {
                return None;
            }
            if let Some(p) = prev_pos {
                if pos <= p {
                    return None;
                }
            }
            prev_pos = Some(pos);
        }

        hint_count = end;
    }

    // Verify unused hint slots are zero (canonical encoding per FIPS 204).
    // This prevents signature malleability where non-zero padding would be ignored.
    for i in hint_count..OMEGA {
        if h[i] != 0 {
            return None;
        }
    }

    Some(hint_count)
}

/// Apply hint vector to w' to recover w'1 = UseHint(h, w').
///
/// # Preconditions
///
/// `h` must be a validated, canonically encoded hint slice of length `OMEGA + K`
/// (as verified by [`validate_hints`]). Hint positions must be strictly increasing
/// within each polynomial partition.
fn apply_hints<const K: usize, const OMEGA: usize>(
    w_prime: &PolyVecK<K>,
    h: &[u8],
    gamma2: i32,
) -> PolyVecK<K> {
    let mut w1_prime = PolyVecK::<K>::zero();
    let mut hint_idx = 0;
    for i in 0..K {
        let end = h[OMEGA + i] as usize;
        for j in 0..N {
            // Hint positions are strictly increasing (guaranteed by validate_hints),
            // so each position j matches at most once — `if` suffices over `while`.
            let hint_val = if hint_idx < end && h[hint_idx] as usize == j {
                hint_idx += 1;
                1
            } else {
                0
            };
            w1_prime.polys[i].coeffs[j] =
                use_hint(hint_val, freeze(w_prime.polys[i].coeffs[j]), gamma2);
        }
        debug_assert_eq!(hint_idx, end, "apply_hints: hint_idx drift at poly {i}");
    }
    w1_prime
}

/// Encode w1 polynomial vector for hashing.
///
/// The encoding length depends on the ML-DSA parameter set via `gamma2`:
/// - `(Q - 1) / 32 = 261_888` → 128 bytes per polynomial (ML-DSA-65/87)
/// - `(Q - 1) / 88 =  95_232` → 192 bytes per polynomial (ML-DSA-44)
fn encode_w1<const K: usize>(w1: &PolyVecK<K>, gamma2: i32) -> Vec<u8> {
    let w1_bytes = match gamma2 {
        261_888 => 128,
        95_232 => 192,
        _ => unreachable!("encode_w1: unsupported gamma2 value {gamma2}"),
    };
    let mut w1_encoded = vec![0u8; K * w1_bytes];
    for i in 0..K {
        pack_w1(
            &w1.polys[i],
            gamma2,
            &mut w1_encoded[i * w1_bytes..(i + 1) * w1_bytes],
        );
    }
    w1_encoded
}

/// Parse z vector from signature bytes.
///
/// # Panics
///
/// Panics if `sig` is shorter than `c_tilde_bytes + L * z_bytes`.
/// Callers must validate signature length before calling this function.
fn parse_z<const L: usize>(
    sig: &[u8],
    c_tilde_bytes: usize,
    gamma1_bits: u32,
    z_bytes: usize,
) -> PolyVecL<L> {
    assert!(
        sig.len() >= c_tilde_bytes + L * z_bytes,
        "parse_z: sig too short ({} < {})",
        sig.len(),
        c_tilde_bytes + L * z_bytes
    );
    let mut z = PolyVecL::<L>::zero();
    for i in 0..L {
        let offset = c_tilde_bytes + i * z_bytes;
        match gamma1_bits {
            17 => unpack_z_17(&sig[offset..offset + z_bytes], &mut z.polys[i]),
            19 => unpack_z_19(&sig[offset..offset + z_bytes], &mut z.polys[i]),
            _ => unreachable!("parse_z: unsupported gamma1_bits {gamma1_bits}"),
        }
    }
    z
}

/// Compute MakeHint vector for the signature.
///
/// Writes hint encoding into `h` (length `OMEGA + K`). Returns `Some(())`
/// on success, or `None` if too many hints (caller should retry with a new mask).
fn compute_hints<const K: usize, const OMEGA: usize>(
    w: &PolyVecK<K>,
    cs2: &PolyVecK<K>,
    ct0: &PolyVecK<K>,
    gamma2: i32,
    h: &mut [u8],
) -> Option<()> {
    debug_assert_eq!(h.len(), OMEGA + K);
    h.fill(0);
    let mut hint_count = 0;

    for i in 0..K {
        for j in 0..N {
            // w' = w - cs2 + ct0 (what verify will compute)
            let w_prime = w.polys[i].coeffs[j] - cs2.polys[i].coeffs[j] + ct0.polys[i].coeffs[j];

            // FIPS 204: MakeHint(z, r) returns 1 if HighBits(r) ≠ HighBits(r+z)
            // We want hint=1 when HighBits(w') ≠ HighBits(w)
            // With r = w', r + z = w, so z = w - w' = cs2 - ct0
            let hint_z = cs2.polys[i].coeffs[j] - ct0.polys[i].coeffs[j];
            let hint = make_hint(freeze(hint_z), freeze(w_prime), gamma2);
            if hint != 0 {
                if hint_count >= OMEGA {
                    return None;
                }
                h[hint_count] = j as u8;
                hint_count += 1;
            }
        }
        h[OMEGA + i] = hint_count as u8;
    }

    Some(())
}

/// Center z coefficients and encode signature: `c_tilde || z || h`.
fn encode_signature<
    const K: usize,
    const L: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    c_tilde: &[u8],
    z: &PolyVecL<L>,
    h: &[u8],
    gamma1_bits: u32,
) -> Vec<u8> {
    assert_eq!(c_tilde.len(), C_TILDE_BYTES, "c_tilde length mismatch");
    assert_eq!(h.len(), OMEGA + K, "hint length mismatch");
    let z_bytes = match gamma1_bits {
        17 => 576,
        19 => 640,
        _ => unreachable!("encode_signature: unsupported gamma1_bits {gamma1_bits}"),
    };
    let sig_size = C_TILDE_BYTES + L * z_bytes + OMEGA + K;
    let mut sig = Vec::with_capacity(sig_size);

    sig.extend_from_slice(c_tilde);

    // Center and pack z one polynomial at a time to avoid cloning the entire
    // PolyVecL (up to 7KB for ML-DSA-87). Only a single Poly (1KB) is needed.
    let mut z_buf = [0u8; 640]; // max(576, 640)
    let mut centered = Poly::zero();
    for i in 0..L {
        for j in 0..N {
            let mut c = z.polys[i].coeffs[j];
            if c > (Q - 1) / 2 {
                c -= Q;
            }
            centered.coeffs[j] = c;
        }
        match gamma1_bits {
            17 => pack_z_17(&centered, &mut z_buf[..z_bytes]),
            19 => pack_z_19(&centered, &mut z_buf[..z_bytes]),
            _ => unreachable!("encode_signature: unsupported gamma1_bits {gamma1_bits}"),
        }
        sig.extend_from_slice(&z_buf[..z_bytes]);
    }

    // Zeroize intermediate buffers that held sensitive z data
    centered.zeroize();
    z_buf.zeroize();

    sig.extend_from_slice(&h[..OMEGA + K]);
    sig
}

// ---------------------------------------------------------------------------
// Expanded verification
// ---------------------------------------------------------------------------

/// Expanded verification key with pre-computed values for fast repeated verification.
///
/// This structure stores pre-computed values that would otherwise be
/// recomputed on every `verify()` call:
/// - `a_hat`: Expanded matrix A in NTT domain
/// - `t1_2d_hat`: t1 * 2^D in NTT domain
/// - `tr`: Hash of public key (H(pk))
///
/// # Usage
///
/// ```ignore
/// let pk = VerificationKey::from_bytes(&pk_bytes)?;
/// let expanded = pk.expand()?;
///
/// // Fast repeated verification of multiple signatures
/// for (msg, sig) in messages_and_signatures {
///     MlDsa65::verify_expanded(&expanded, msg, &sig)?;
/// }
/// ```
///
/// # Performance
///
/// Timings vary by parameter set. Example for ML-DSA-65:
///
/// | Operation | Time |
/// |-----------|------|
/// | `expand()` | ~68 µs |
/// | `verify_expanded()` | ~38 µs |
/// | `verify()` (regular) | ~101 µs |
///
/// Break-even point: 2 verifications with the same key.
pub struct ExpandedVerificationKey<const K: usize, const L: usize> {
    /// Expanded matrix A in NTT domain
    pub(crate) a_hat: Matrix<K, L>,
    /// t1 * 2^D in NTT domain
    pub(crate) t1_2d_hat: PolyVecK<K>,
    /// Hash of public key: tr = H(pk)
    pub(crate) tr: [u8; 64],
}

/// Expand a verification key for fast repeated verification.
///
/// Pre-computes:
/// - `expand_a()`: K×L polynomials from SHAKE128 (most expensive)
/// - `hash_pk()`: SHA3-512 hash of public key
/// - `t1 * 2^D` in NTT domain
pub fn expand_verification_key<const K: usize, const L: usize>(
    pk: &[u8],
) -> Option<ExpandedVerificationKey<K, L>> {
    if pk.len() < 32 + K * 320 {
        return None;
    }

    // Parse rho from public key
    let rho: [u8; 32] = pk[0..32].try_into().ok()?;

    // Unpack t1
    let mut t1 = PolyVecK::<K>::zero();
    for i in 0..K {
        let offset = 32 + i * 320;
        unpack_t1(&pk[offset..offset + 320], &mut t1.polys[i]);
    }

    // Pre-compute expand_a
    let a_hat = expand_a::<K, L>(&rho);

    // Pre-compute t1 * 2^D in NTT domain
    let mut t1_2d_hat = t1;
    for p in &mut t1_2d_hat.polys {
        for c in &mut p.coeffs {
            *c <<= D;
        }
    }
    t1_2d_hat.ntt();

    // Pre-compute tr = H(pk)
    let tr = hash_pk(pk);

    Some(ExpandedVerificationKey {
        a_hat,
        t1_2d_hat,
        tr,
    })
}

/// ML-DSA Verify using pre-expanded verification key.
///
/// This is faster than `ml_dsa_verify` when verifying multiple signatures
/// with the same public key.
pub fn ml_dsa_verify_expanded<
    const K: usize,
    const L: usize,
    const BETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const TAU: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    expanded: &ExpandedVerificationKey<K, L>,
    message: &[u8],
    sig: &[u8],
) -> bool {
    let gamma1_bits = if GAMMA1 == (1 << 17) { 17 } else { 19 };
    let z_bytes = if gamma1_bits == 17 { 576 } else { 640 };
    let expected_sig_len = C_TILDE_BYTES + L * z_bytes + OMEGA + K;

    if sig.len() != expected_sig_len {
        return false;
    }

    // Parse signature
    let c_tilde = &sig[0..C_TILDE_BYTES];
    let z = parse_z::<L>(sig, C_TILDE_BYTES, gamma1_bits, z_bytes);

    let h_start = C_TILDE_BYTES + L * z_bytes;
    let h = &sig[h_start..];

    if !z.check_norm(GAMMA1 - BETA) {
        return false;
    }

    if validate_hints::<K, OMEGA>(h).is_none() {
        return false;
    }

    // Use pre-computed tr
    let mu = hash_message(&expanded.tr, message);

    // c = SampleInBall(c_tilde)
    let c = sample_in_ball(c_tilde, TAU);

    // NTT of c, z
    let mut c_hat = c.clone();
    c_hat.ntt();

    let mut z_hat = z.clone();
    z_hat.ntt();

    // Use pre-computed a_hat and t1_2d_hat
    // w' = A*z - c * (t1 * 2^d) (in NTT domain)
    let mut az = expanded.a_hat.mul_vec(&z_hat);
    az.reduce();

    let mut ct1_2d = PolyVecK::<K>::zero();
    for i in 0..K {
        ct1_2d.polys[i] = c_hat.pointwise_mul(&expanded.t1_2d_hat.polys[i]);
    }
    ct1_2d.reduce();

    let mut w_prime = az.sub(&ct1_2d);
    w_prime.reduce();
    w_prime.inv_ntt();
    w_prime.caddq();

    // Apply hints to get w'1
    let w1_prime = apply_hints::<K, OMEGA>(&w_prime, h, GAMMA2);
    let w1_encoded = encode_w1::<K>(&w1_prime, GAMMA2);

    // c_tilde' = H(mu || w1Encode(w'1))
    let mut c_tilde_prime = [0u8; 64];
    h2(&mu, &w1_encoded, &mut c_tilde_prime);

    // Verify c_tilde == c_tilde'
    c_tilde == &c_tilde_prime[..C_TILDE_BYTES]
}

// ---------------------------------------------------------------------------
// Key generation helpers
// ---------------------------------------------------------------------------

/// Expand matrix A from seed rho.
pub fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> Matrix<K, L> {
    let mut a = Matrix::<K, L>::zero();

    for i in 0..K {
        for j in 0..L {
            let mut xof = Shake128Xof::new(rho, i as u8, j as u8);
            a.rows[i].polys[j] = sample_ntt(&mut xof);
        }
    }

    a
}

/// Expand secret vectors s1, s2 from seed rho'.
pub fn expand_s<const K: usize, const L: usize, const ETA: usize>(
    rho_prime: &[u8],
) -> (PolyVecL<L>, PolyVecK<K>) {
    let mut s1 = PolyVecL::<L>::zero();
    let mut s2 = PolyVecK::<K>::zero();

    for i in 0..L {
        s1.polys[i] = sample_eta::<ETA>(rho_prime, i as u16);
    }

    for i in 0..K {
        s2.polys[i] = sample_eta::<ETA>(rho_prime, (L + i) as u16);
    }

    (s1, s2)
}

// ---------------------------------------------------------------------------
// ML-DSA.KeyGen (Algorithm 1)
// ---------------------------------------------------------------------------

/// ML-DSA Key Generation (Algorithm 1 - ML-DSA.KeyGen_internal)
///
/// Returns (sk, pk) where:
/// - sk = (rho, K, tr, s1, s2, t0)
/// - pk = (rho, t1)
pub fn ml_dsa_keygen<const K: usize, const L: usize, const ETA: usize>(
    xi: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    // 1. Expand seed with domain separation: (rho, rho', K) = H(xi || k || l, 128)
    // Per FIPS 204 Algorithm 1, step 1
    let mut seed_input = [0u8; 34];
    seed_input[..32].copy_from_slice(xi);
    seed_input[32] = K as u8;
    seed_input[33] = L as u8;

    let mut expanded = [0u8; 128];
    h(&seed_input, &mut expanded);

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key_k = [0u8; 32];

    rho.copy_from_slice(&expanded[0..32]);
    rho_prime.copy_from_slice(&expanded[32..96]);
    key_k.copy_from_slice(&expanded[96..128]);

    // 2. Sample matrix A
    let a = expand_a::<K, L>(&rho);

    // 3. Sample secret vectors s1, s2
    let (mut s1, mut s2) = expand_s::<K, L, ETA>(&rho_prime);

    // 4. Compute t = A * s1 + s2
    let mut s1_ntt = s1.clone();
    s1_ntt.ntt();

    let mut t = a.mul_vec(&s1_ntt);
    t.reduce();
    t.inv_ntt();
    t.caddq();
    t.add_assign(&s2);
    t.caddq();

    // 5. Power2Round: (t1, t0) = Power2Round(t)
    let mut t1 = PolyVecK::<K>::zero();
    let mut t0 = PolyVecK::<K>::zero();

    for i in 0..K {
        for j in 0..N {
            let (t1_j, t0_j) = power2round(t.polys[i].coeffs[j]);
            t1.polys[i].coeffs[j] = t1_j;
            t0.polys[i].coeffs[j] = t0_j;
        }
    }

    // 6. Pack public key: pk = rho || t1
    let mut pk = Vec::with_capacity(32 + K * 320);
    pk.extend_from_slice(&rho);
    for i in 0..K {
        let mut buf = [0u8; 320];
        pack_t1(&t1.polys[i], &mut buf);
        pk.extend_from_slice(&buf);
    }

    // 7. Compute tr = H(pk)
    let tr = hash_pk(&pk);

    // 8. Pack secret key: sk = rho || K || tr || s1 || s2 || t0
    let eta_bytes = if ETA == 2 { 96 } else { 128 };
    let sk_size = 32 + 32 + 64 + L * eta_bytes + K * eta_bytes + K * 416;
    let mut sk = Vec::with_capacity(sk_size);

    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&key_k);
    sk.extend_from_slice(&tr);

    // Pack s1 and s2 using a single reusable buffer
    let mut eta_buf = vec![0u8; eta_bytes];
    for i in 0..L {
        if ETA == 2 {
            pack_eta2(&s1.polys[i], &mut eta_buf);
        } else {
            pack_eta4(&s1.polys[i], &mut eta_buf);
        }
        sk.extend_from_slice(&eta_buf);
    }

    // Pack s2
    for i in 0..K {
        if ETA == 2 {
            pack_eta2(&s2.polys[i], &mut eta_buf);
        } else {
            pack_eta4(&s2.polys[i], &mut eta_buf);
        }
        sk.extend_from_slice(&eta_buf);
    }
    eta_buf.zeroize(); // Zeroize buffer that held secret key material

    // Pack t0
    for i in 0..K {
        let mut buf = [0u8; 416];
        pack_t0(&t0.polys[i], &mut buf);
        sk.extend_from_slice(&buf);
    }

    // Zeroize sensitive data
    seed_input.zeroize();
    expanded.zeroize();
    rho_prime.zeroize();
    key_k.zeroize();
    s1.zeroize();
    s2.zeroize();
    t0.zeroize();

    (sk, pk)
}

// ---------------------------------------------------------------------------
// ML-DSA.Sign (Algorithm 2)
// ---------------------------------------------------------------------------

/// ML-DSA Sign (Algorithm 2)
///
/// Signs message with secret key, optionally using randomness rnd.
pub fn ml_dsa_sign<
    const K: usize,
    const L: usize,
    const ETA: usize,
    const BETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const TAU: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    sk: &[u8],
    message: &[u8],
    rnd: &[u8; 32],
) -> Option<Vec<u8>> {
    let eta_bytes = if ETA == 2 { 96 } else { 128 };
    let gamma1_bits = if GAMMA1 == (1 << 17) { 17 } else { 19 };

    // Parse secret key
    let rho = &sk[0..32];
    let key_k = &sk[32..64];
    let tr: &[u8; 64] = sk[64..128].try_into().ok()?;

    let s1_start = 128;
    let s2_start = s1_start + L * eta_bytes;
    let t0_start = s2_start + K * eta_bytes;

    // Unpack s1
    let mut s1 = PolyVecL::<L>::zero();
    for i in 0..L {
        let offset = s1_start + i * eta_bytes;
        if ETA == 2 {
            unpack_eta2(&sk[offset..offset + eta_bytes], &mut s1.polys[i]);
        } else {
            unpack_eta4(&sk[offset..offset + eta_bytes], &mut s1.polys[i]);
        }
    }

    // Unpack s2
    let mut s2 = PolyVecK::<K>::zero();
    for i in 0..K {
        let offset = s2_start + i * eta_bytes;
        if ETA == 2 {
            unpack_eta2(&sk[offset..offset + eta_bytes], &mut s2.polys[i]);
        } else {
            unpack_eta4(&sk[offset..offset + eta_bytes], &mut s2.polys[i]);
        }
    }

    // Unpack t0
    let mut t0 = PolyVecK::<K>::zero();
    for i in 0..K {
        let offset = t0_start + i * 416;
        unpack_t0(&sk[offset..offset + 416], &mut t0.polys[i]);
    }

    // Expand A
    let mut rho_arr = [0u8; 32];
    rho_arr.copy_from_slice(rho);
    let a = expand_a::<K, L>(&rho_arr);

    // Compute mu = H(tr || M)
    let mu = hash_message(tr, message);

    // Compute rho' = H(K || rnd || mu)
    // Use h3 directly to avoid heap allocation with secret key material
    let mut rho_prime = [0u8; 64];
    crate::hash::h3(key_k, rnd, &mu, &mut rho_prime);

    // NTT of s1, s2, t0
    let mut s1_hat = s1.clone();
    s1_hat.ntt();
    let mut s2_hat = s2.clone();
    s2_hat.ntt();
    let mut t0_hat = t0.clone();
    t0_hat.ntt();

    // Rejection sampling loop
    // Use u32 for kappa to avoid overflow with larger L values
    let mut kappa: u32 = 0;
    // Safety limit for rejection sampling.
    //
    // For the ML-DSA parameter sets we target, the expected number of
    // rejection-sampling iterations is very small (typically 1–2 attempts,
    // and only rarely more than a handful). Setting MAX_ATTEMPTS to 10,000
    // therefore gives an extremely conservative upper bound: under normal
    // operation this limit is never reached, while still providing a hard
    // cap to prevent an unbounded loop in the presence of malformed inputs,
    // implementation bugs, or hardware faults. In other words, 10,000 is
    // chosen to be orders of magnitude larger than any realistic number of
    // attempts, making the probability of hitting this limit negligibly
    // small while retaining a clear safety guard.
    const MAX_ATTEMPTS: u32 = 10000;
    let mut h = vec![0u8; OMEGA + K];
    loop {
        if kappa >= MAX_ATTEMPTS {
            // Zeroize sensitive values before returning on failure path
            rho_prime.zeroize();
            s1.zeroize();
            s2.zeroize();
            t0.zeroize();
            s1_hat.zeroize();
            s2_hat.zeroize();
            t0_hat.zeroize();
            return None;
        }

        // Sample y
        let mut y = PolyVecL::<L>::zero();
        let base_nonce = kappa * (L as u32);
        for i in 0..L {
            let nonce = base_nonce + (i as u32);
            y.polys[i] = sample_mask(&rho_prime, nonce as u16, gamma1_bits);
        }

        // w = A * NTT(y)
        let mut y_hat = y.clone();
        y_hat.ntt();

        let mut w = a.mul_vec(&y_hat);
        w.reduce();
        w.inv_ntt();
        w.caddq();

        // w1 = HighBits(w)
        let mut w1 = PolyVecK::<K>::zero();
        for i in 0..K {
            for j in 0..N {
                w1.polys[i].coeffs[j] = highbits(w.polys[i].coeffs[j], GAMMA2);
            }
        }

        // c_tilde = H(mu || w1Encode(w1))
        let w1_encoded = encode_w1::<K>(&w1, GAMMA2);

        let mut c_tilde_full = [0u8; 64]; // Full hash output
        h2(&mu, &w1_encoded, &mut c_tilde_full);
        let c_tilde = &c_tilde_full[..C_TILDE_BYTES];

        // c = SampleInBall(c_tilde)
        let c = sample_in_ball(c_tilde, TAU);

        // z = y + c * s1
        let mut c_hat = c.clone();
        c_hat.ntt();

        let mut z = PolyVecL::<L>::zero();
        for i in 0..L {
            let mut cs1_poly = c_hat.pointwise_mul(&s1_hat.polys[i]);
            cs1_poly.reduce();
            crate::ntt::inv_ntt(&mut cs1_poly.coeffs);
            cs1_poly.caddq();
            z.polys[i] = y.polys[i].add(&cs1_poly);
        }

        z.reduce();

        // Check ||z||_inf < gamma1 - beta
        if !z.check_norm(GAMMA1 - BETA) {
            kappa += 1;
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            continue;
        }

        // r0 = LowBits(w - c*s2)
        let mut cs2 = PolyVecK::<K>::zero();
        for i in 0..K {
            cs2.polys[i] = c_hat.pointwise_mul(&s2_hat.polys[i]);
        }
        cs2.reduce();
        cs2.inv_ntt();
        cs2.caddq();

        let mut r0 = PolyVecK::<K>::zero();
        for i in 0..K {
            for j in 0..N {
                let wcs2 = w.polys[i].coeffs[j] - cs2.polys[i].coeffs[j];
                r0.polys[i].coeffs[j] = lowbits(freeze(wcs2), GAMMA2);
            }
        }

        // Check ||r0||_inf < gamma2 - beta
        if !r0.check_norm(GAMMA2 - BETA) {
            kappa += 1;
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            cs2.zeroize();
            r0.zeroize();
            continue;
        }

        // Compute c*t0
        let mut ct0 = PolyVecK::<K>::zero();
        for i in 0..K {
            ct0.polys[i] = c_hat.pointwise_mul(&t0_hat.polys[i]);
        }
        ct0.reduce();
        ct0.inv_ntt();
        ct0.caddq();

        // Check ||ct0||_inf < gamma2 (FIPS 204 Algorithm 2, step 25)
        if !ct0.check_norm(GAMMA2) {
            kappa += 1;
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            cs2.zeroize();
            r0.zeroize();
            ct0.zeroize();
            continue;
        }

        // Compute hints
        if compute_hints::<K, OMEGA>(&w, &cs2, &ct0, GAMMA2, &mut h).is_none() {
            kappa += 1;
            y.zeroize();
            y_hat.zeroize();
            w.zeroize();
            cs2.zeroize();
            r0.zeroize();
            ct0.zeroize();
            continue;
        }

        // Encode signature: c_tilde || z || h
        let sig = encode_signature::<K, L, OMEGA, C_TILDE_BYTES>(c_tilde, &z, &h, gamma1_bits);

        // Zeroize loop-scoped sensitive values. y is critical: if leaked
        // alongside the signature (c, z), s1 can be recovered via z = y + c*s1.
        y.zeroize();
        y_hat.zeroize();
        w.zeroize();
        cs2.zeroize();
        r0.zeroize();
        ct0.zeroize();

        // Zeroize long-lived sensitive intermediate values before returning
        rho_prime.zeroize();
        s1.zeroize();
        s2.zeroize();
        t0.zeroize();
        s1_hat.zeroize();
        s2_hat.zeroize();
        t0_hat.zeroize();

        return Some(sig);
    }
}

// ---------------------------------------------------------------------------
// ML-DSA.Verify (Algorithm 3)
// ---------------------------------------------------------------------------

/// ML-DSA Verify (Algorithm 3)
///
/// Verifies signature on message with public key.
pub fn ml_dsa_verify<
    const K: usize,
    const L: usize,
    const BETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const TAU: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    pk: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let gamma1_bits = if GAMMA1 == (1 << 17) { 17 } else { 19 };
    let z_bytes = if gamma1_bits == 17 { 576 } else { 640 };
    let expected_sig_len = C_TILDE_BYTES + L * z_bytes + OMEGA + K;

    if sig.len() != expected_sig_len {
        return false;
    }

    // Parse public key
    let rho: [u8; 32] = match pk[0..32].try_into() {
        Ok(r) => r,
        Err(_) => return false,
    };

    let mut t1 = PolyVecK::<K>::zero();
    for i in 0..K {
        let offset = 32 + i * 320;
        unpack_t1(&pk[offset..offset + 320], &mut t1.polys[i]);
    }

    // Parse signature
    let c_tilde = &sig[0..C_TILDE_BYTES];
    let z = parse_z::<L>(sig, C_TILDE_BYTES, gamma1_bits, z_bytes);

    let h_start = C_TILDE_BYTES + L * z_bytes;
    let h = &sig[h_start..];

    // Check z norm
    if !z.check_norm(GAMMA1 - BETA) {
        return false;
    }

    // Validate hint encoding per FIPS 204 canonical requirements
    if validate_hints::<K, OMEGA>(h).is_none() {
        return false;
    }

    // Compute tr = H(pk)
    let tr = hash_pk(pk);

    // Compute mu = H(tr || M)
    let mu = hash_message(&tr, message);

    // Expand A
    let a = expand_a::<K, L>(&rho);

    // c = SampleInBall(c_tilde)
    let c = sample_in_ball(c_tilde, TAU);

    // NTT of c, z
    let mut c_hat = c.clone();
    c_hat.ntt();

    let mut z_hat = z.clone();
    z_hat.ntt();

    // Scale t1 by 2^d first, then NTT
    // w' = A*z - c * (t1 * 2^d)
    let mut t1_scaled = PolyVecK::<K>::zero();
    for i in 0..K {
        for j in 0..N {
            t1_scaled.polys[i].coeffs[j] = t1.polys[i].coeffs[j] << D;
        }
    }
    t1_scaled.ntt();

    // Compute A*z - c*(t1*2^d) in NTT domain
    let mut az = a.mul_vec(&z_hat);
    az.reduce();

    let mut ct1_2d = PolyVecK::<K>::zero();
    for i in 0..K {
        ct1_2d.polys[i] = c_hat.pointwise_mul(&t1_scaled.polys[i]);
    }
    ct1_2d.reduce();

    // w' = A*z - c*t1*2^d (in NTT domain)
    let mut w_prime = az.sub(&ct1_2d);
    w_prime.reduce();
    w_prime.inv_ntt();
    w_prime.caddq();

    // Apply hints to get w'1
    let w1_prime = apply_hints::<K, OMEGA>(&w_prime, h, GAMMA2);
    let w1_encoded = encode_w1::<K>(&w1_prime, GAMMA2);

    // c_tilde' = H(mu || w1Encode(w'1))
    let mut c_tilde_prime = [0u8; 64];
    h2(&mu, &w1_encoded, &mut c_tilde_prime);

    // Verify c_tilde == c_tilde'
    c_tilde == &c_tilde_prime[..C_TILDE_BYTES]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_a_deterministic() {
        let rho = [0u8; 32];
        let a1 = expand_a::<4, 4>(&rho);
        let a2 = expand_a::<4, 4>(&rho);

        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(a1.rows[i].polys[j].coeffs, a2.rows[i].polys[j].coeffs);
            }
        }
    }

    #[test]
    fn test_keygen_produces_valid_sizes() {
        let xi = [42u8; 32];
        let (sk, pk) = ml_dsa_keygen::<4, 4, 2>(&xi);

        // ML-DSA-44: pk = 1312, sk = 2560
        assert_eq!(pk.len(), 1312);
        assert_eq!(sk.len(), 2560);
    }

    /// Verify the fundamental identity: A*s1 = t1*2^d + t0 - s2
    /// This is critical for the sign/verify relationship to hold.
    #[test]
    fn test_keygen_identity() {
        let xi = [42u8; 32];
        const K: usize = 4;
        const L: usize = 4;
        const ETA: usize = 2;
        const D: u32 = 13;

        // 1. Expand seed
        let mut expanded = [0u8; 128];
        h(&xi, &mut expanded);
        let mut rho = [0u8; 32];
        let mut rho_prime = [0u8; 64];
        rho.copy_from_slice(&expanded[0..32]);
        rho_prime.copy_from_slice(&expanded[32..96]);

        // 2. Sample A, s1, s2
        let a = expand_a::<K, L>(&rho);
        let (s1, s2) = expand_s::<K, L, ETA>(&rho_prime);

        // 3. Compute A*s1 + s2 = t
        let mut s1_ntt = s1.clone();
        s1_ntt.ntt();
        let mut t = a.mul_vec(&s1_ntt);
        t.reduce();
        t.inv_ntt();
        t.caddq();
        t.add_assign(&s2);
        t.caddq();

        // 4. Power2Round
        let mut t1 = PolyVecK::<K>::zero();
        let mut t0 = PolyVecK::<K>::zero();
        for i in 0..K {
            for j in 0..N {
                let (t1_j, t0_j) = crate::rounding::power2round(t.polys[i].coeffs[j]);
                t1.polys[i].coeffs[j] = t1_j;
                t0.polys[i].coeffs[j] = t0_j;
            }
        }

        // 5. Verify t = t1*2^d + t0
        for i in 0..K {
            for j in 0..N {
                let reconstructed = t1.polys[i].coeffs[j] * (1 << D) + t0.polys[i].coeffs[j];
                assert_eq!(
                    reconstructed, t.polys[i].coeffs[j],
                    "Power2Round identity failed at [{i}][{j}]"
                );
            }
        }

        // 6. Compute A*s1 directly and verify = t - s2 = t1*2^d + t0 - s2
        // First, compute t1*2^d + t0 - s2
        let mut expected = PolyVecK::<K>::zero();
        for i in 0..K {
            for j in 0..N {
                expected.polys[i].coeffs[j] = t1.polys[i].coeffs[j] * (1 << D)
                    + t0.polys[i].coeffs[j]
                    - s2.polys[i].coeffs[j];
            }
        }
        expected.reduce();
        expected.freeze();

        // Now compute A*s1 directly
        let mut as1 = a.mul_vec(&s1_ntt);
        as1.reduce();
        as1.inv_ntt();
        as1.caddq();

        // Compare
        for i in 0..K {
            for j in 0..N {
                let a = freeze(as1.polys[i].coeffs[j]);
                let e = freeze(expected.polys[i].coeffs[j]);
                assert_eq!(
                    a, e,
                    "A*s1 != t1*2^d + t0 - s2 at [{i}][{j}]: A*s1={a}, expected={e}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // validate_hints tests
    // -----------------------------------------------------------------------

    /// Use ML-DSA-44 parameters for hint tests: K=4, OMEGA=80.
    const TEST_K: usize = 4;
    const TEST_OMEGA: usize = 80;
    const TEST_H_LEN: usize = TEST_OMEGA + TEST_K; // 84

    /// Valid encoding with zero hints.
    #[test]
    fn test_validate_hints_empty() {
        let h = [0u8; TEST_H_LEN];
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), Some(0));
    }

    /// Valid encoding with one hint in the first polynomial.
    #[test]
    fn test_validate_hints_single_hint() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 42; // hint at position 42 in poly 0
        h[TEST_OMEGA] = 1; // poly 0 has 1 hint
        h[TEST_OMEGA + 1] = 1;
        h[TEST_OMEGA + 2] = 1;
        h[TEST_OMEGA + 3] = 1;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), Some(1));
    }

    /// Valid encoding with hints across multiple polynomials.
    #[test]
    fn test_validate_hints_multi_poly() {
        let mut h = [0u8; TEST_H_LEN];
        // Poly 0: hints at positions 10, 20
        h[0] = 10;
        h[1] = 20;
        h[TEST_OMEGA] = 2;
        // Poly 1: hint at position 5
        h[2] = 5;
        h[TEST_OMEGA + 1] = 3;
        // Poly 2: no hints
        h[TEST_OMEGA + 2] = 3;
        // Poly 3: hint at position 100
        h[3] = 100;
        h[TEST_OMEGA + 3] = 4;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), Some(4));
    }

    /// Wrong length (too short).
    #[test]
    fn test_validate_hints_wrong_length_short() {
        let h = [0u8; TEST_H_LEN - 1];
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// Wrong length (too long).
    #[test]
    fn test_validate_hints_wrong_length_long() {
        let h = [0u8; TEST_H_LEN + 1];
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// Hint position at maximum valid value (N-1 = 255).
    #[test]
    fn test_validate_hints_max_valid_position() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 255; // N-1, valid
        h[TEST_OMEGA] = 1;
        h[TEST_OMEGA + 1] = 1;
        h[TEST_OMEGA + 2] = 1;
        h[TEST_OMEGA + 3] = 1;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), Some(1));
    }

    /// Non-strictly-increasing positions within a polynomial.
    #[test]
    fn test_validate_hints_non_increasing() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 20;
        h[1] = 10; // out of order
        h[TEST_OMEGA] = 2;
        h[TEST_OMEGA + 1] = 2;
        h[TEST_OMEGA + 2] = 2;
        h[TEST_OMEGA + 3] = 2;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// Duplicate positions (equal, not strictly increasing).
    #[test]
    fn test_validate_hints_duplicate_positions() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 10;
        h[1] = 10; // duplicate
        h[TEST_OMEGA] = 2;
        h[TEST_OMEGA + 1] = 2;
        h[TEST_OMEGA + 2] = 2;
        h[TEST_OMEGA + 3] = 2;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// end > OMEGA is invalid.
    #[test]
    fn test_validate_hints_end_exceeds_omega() {
        let mut h = [0u8; TEST_H_LEN];
        h[TEST_OMEGA] = (TEST_OMEGA + 1) as u8; // end > OMEGA
        h[TEST_OMEGA + 1] = (TEST_OMEGA + 1) as u8;
        h[TEST_OMEGA + 2] = (TEST_OMEGA + 1) as u8;
        h[TEST_OMEGA + 3] = (TEST_OMEGA + 1) as u8;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// end < start (non-monotonic cumulative counts).
    #[test]
    fn test_validate_hints_end_less_than_start() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 5;
        h[TEST_OMEGA] = 2; // poly 0 ends at 2
        h[TEST_OMEGA + 1] = 1; // poly 1 ends at 1, but start = 2 → invalid
        h[TEST_OMEGA + 2] = 1;
        h[TEST_OMEGA + 3] = 1;
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }

    /// Non-zero bytes in unused hint slots (malleability).
    #[test]
    fn test_validate_hints_nonzero_unused_slots() {
        let mut h = [0u8; TEST_H_LEN];
        h[0] = 10;
        h[TEST_OMEGA] = 1;
        h[TEST_OMEGA + 1] = 1;
        h[TEST_OMEGA + 2] = 1;
        h[TEST_OMEGA + 3] = 1;
        h[1] = 0xFF; // non-zero in unused slot
        assert_eq!(validate_hints::<TEST_K, TEST_OMEGA>(&h), None);
    }
}
