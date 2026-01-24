//! Core ML-DSA signing algorithms
//!
//! Implements KeyGen, Sign, Verify per FIPS 204.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use crate::hash::{h, h2, hash_message, hash_pk, Shake128Xof};
use crate::packing::*;
use crate::poly::N;
use crate::polyvec::{Matrix, PolyVecK, PolyVecL};
use crate::reduce::{freeze, Q};
use crate::rounding::{highbits, lowbits, make_hint, power2round, use_hint, D};
use crate::sample::{sample_eta, sample_in_ball, sample_mask, sample_ntt};

use zeroize::Zeroize;

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

    // Pack s1
    for i in 0..L {
        let mut buf = vec![0u8; eta_bytes];
        if ETA == 2 {
            pack_eta2(&s1.polys[i], &mut buf);
        } else {
            pack_eta4(&s1.polys[i], &mut buf);
        }
        sk.extend_from_slice(&buf);
    }

    // Pack s2
    for i in 0..K {
        let mut buf = vec![0u8; eta_bytes];
        if ETA == 2 {
            pack_eta2(&s2.polys[i], &mut buf);
        } else {
            pack_eta4(&s2.polys[i], &mut buf);
        }
        sk.extend_from_slice(&buf);
    }

    // Pack t0
    for i in 0..K {
        let mut buf = [0u8; 416];
        pack_t0(&t0.polys[i], &mut buf);
        sk.extend_from_slice(&buf);
    }

    // Zeroize sensitive data
    expanded.zeroize();
    rho_prime.zeroize();
    key_k.zeroize();
    s1.zeroize();
    s2.zeroize();
    t0.zeroize();

    (sk, pk)
}

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
    let z_bytes = if gamma1_bits == 17 { 576 } else { 640 };

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
    loop {
        if kappa >= MAX_ATTEMPTS {
            return None; // Signing failed after too many attempts
        }

        // Sample y
        let mut y = PolyVecL::<L>::zero();
        let base_nonce = kappa * (L as u32);
        for i in 0..L {
            let nonce = base_nonce + (i as u32);
            y.polys[i] = sample_mask(&rho_prime, nonce as u16, gamma1_bits);
        }

        #[cfg(test)]
        if kappa == 0 {
            let max_y = y.polys.iter().map(|p| p.norm_inf()).max().unwrap_or(0);
            eprintln!("SIGN: max ||y||_inf = {}, gamma1 = {}", max_y, GAMMA1);
        }

        // w = A * NTT(y)
        let mut y_hat = y.clone();
        y_hat.ntt();

        #[cfg(test)]
        {
            eprintln!(
                "SIGN: A[0][0].coeffs[0..4] = {:?}",
                &a.rows[0].polys[0].coeffs[0..4]
            );
            eprintln!(
                "SIGN: y_hat[0].coeffs[0..4] = {:?}",
                &y_hat.polys[0].coeffs[0..4]
            );
        }

        let ay_ntt = a.mul_vec(&y_hat); // A*y in NTT domain (before reduce)

        #[cfg(test)]
        {
            eprintln!(
                "SIGN: (A*y)_ntt[0].coeffs[0..4] = {:?}",
                &ay_ntt.polys[0].coeffs[0..4]
            );
        }

        // Clone for later use in debugging
        #[cfg(test)]
        let ay_ntt_copy = ay_ntt.clone();

        let mut w = ay_ntt;
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

        #[cfg(test)]
        {
            eprintln!("SIGN: w[0][12..20] = {:?}", &w.polys[0].coeffs[12..20]);
            eprintln!("SIGN: w1[0][12..20] = {:?}", &w1.polys[0].coeffs[12..20]);
        }

        // c_tilde = H(mu || w1Encode(w1))
        let w1_bytes = if GAMMA2 == 261888 { 128 } else { 192 };
        let mut w1_encoded = vec![0u8; K * w1_bytes];
        for i in 0..K {
            pack_w1(
                &w1.polys[i],
                GAMMA2,
                &mut w1_encoded[i * w1_bytes..(i + 1) * w1_bytes],
            );
        }

        // Store w1 for comparison with verify
        #[cfg(test)]
        {
            // Print per-polynomial checksums
            let w1_bytes = if GAMMA2 == 261888 { 128 } else { 192 };
            for i in 0..K {
                let start = i * w1_bytes;
                let poly_checksum: u64 = w1_encoded[start..start + w1_bytes]
                    .iter()
                    .map(|&b| b as u64)
                    .sum();
                eprintln!("SIGN: w1[{}] checksum = {}", i, poly_checksum);
            }
        }

        let mut c_tilde_full = [0u8; 64]; // Full hash output
        h2(&mu, &w1_encoded, &mut c_tilde_full);
        let c_tilde = &c_tilde_full[..C_TILDE_BYTES];

        // c = SampleInBall(c_tilde)
        let c = sample_in_ball(&c_tilde, TAU);

        // z = y + c * s1
        let mut c_hat = c.clone();
        c_hat.ntt();

        let mut z = PolyVecL::<L>::zero();
        for i in 0..L {
            let cs1 = c_hat.pointwise_mul(&s1_hat.polys[i]);
            let mut cs1_poly = cs1;
            cs1_poly.reduce();
            crate::ntt::inv_ntt(&mut cs1_poly.coeffs);
            cs1_poly.caddq();

            #[cfg(test)]
            if kappa == 0 && i == 0 {
                let max_cs1 = cs1_poly.norm_inf();
                eprintln!(
                    "SIGN: max ||c*s1[0]||_inf = {}, expected <= tau*eta = {}",
                    max_cs1,
                    TAU * (ETA as usize)
                );
            }

            z.polys[i] = y.polys[i].add(&cs1_poly);
        }

        z.reduce();

        // Check ||z||_inf < gamma1 - beta
        #[cfg(test)]
        if kappa < 5 || kappa % 1000 == 0 {
            let max_z = z.polys.iter().map(|p| p.norm_inf()).max().unwrap_or(0);
            eprintln!(
                "SIGN: kappa={}, max ||z||_inf = {}, bound = {}",
                kappa,
                max_z,
                GAMMA1 - BETA
            );
        }
        if !z.check_norm(GAMMA1 - BETA) {
            kappa += 1;
            continue;
        }

        // r0 = LowBits(w - c*s2)
        let mut cs2 = PolyVecK::<K>::zero();
        for i in 0..K {
            let p = c_hat.pointwise_mul(&s2_hat.polys[i]);
            cs2.polys[i] = p;
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
            continue;
        }

        // Compute hints
        let mut ct0 = PolyVecK::<K>::zero();
        for i in 0..K {
            let p = c_hat.pointwise_mul(&t0_hat.polys[i]);
            ct0.polys[i] = p;
        }
        ct0.reduce();
        ct0.inv_ntt();
        ct0.caddq();

        let mut h = vec![0u8; OMEGA + K];
        let mut hint_count = 0;

        // Store wcs2ct0 for debugging
        #[cfg(test)]
        let mut wcs2ct0_vec = PolyVecK::<K>::zero();

        let mut hint_overflow = false;
        'hint_loop: for i in 0..K {
            for j in 0..N {
                // w' = w - cs2 + ct0 (what verify will compute)
                let w_prime =
                    w.polys[i].coeffs[j] - cs2.polys[i].coeffs[j] + ct0.polys[i].coeffs[j];

                #[cfg(test)]
                {
                    wcs2ct0_vec.polys[i].coeffs[j] = freeze(w_prime);
                }

                // FIPS 204: MakeHint(z, r) returns 1 if HighBits(r) ≠ HighBits(r+z)
                // We want hint=1 when HighBits(w') ≠ HighBits(w)
                // With r = w', r + z = w, so z = w - w' = cs2 - ct0
                let hint_z = cs2.polys[i].coeffs[j] - ct0.polys[i].coeffs[j];
                let hint = make_hint(freeze(hint_z), freeze(w_prime), GAMMA2);
                if hint != 0 {
                    if hint_count >= OMEGA {
                        // Too many hints - need to restart rejection sampling
                        hint_overflow = true;
                        break 'hint_loop;
                    }
                    h[hint_count] = j as u8;
                    hint_count += 1;
                }
            }
            h[OMEGA + i] = hint_count as u8;
        }

        if hint_overflow {
            kappa += 1;
            continue;
        }

        // Compute what verify would see in NTT domain: (A*y - c*s2 + c*t0) in NTT
        // We need to compute: NTT(w - cs2 + ct0) = A*y_hat - c_hat⊙s2_hat + c_hat⊙t0_hat
        #[cfg(test)]
        let expected_w_prime_ntt = {
            // A*y is in ay_ntt_copy (before reduce)
            // c*s2 = c_hat ⊙ s2_hat
            // c*t0 = c_hat ⊙ t0_hat
            let mut result = PolyVecK::<K>::zero();
            for i in 0..K {
                let cs2_ntt = c_hat.pointwise_mul(&s2_hat.polys[i]);
                let ct0_ntt = c_hat.pointwise_mul(&t0_hat.polys[i]);
                for j in 0..N {
                    result.polys[i].coeffs[j] =
                        ay_ntt_copy.polys[i].coeffs[j] - cs2_ntt.coeffs[j] + ct0_ntt.coeffs[j];
                }
            }
            result.reduce();
            result
        };

        #[cfg(test)]
        {
            eprintln!(
                "SIGN: expected_w'_ntt[0][0..4] = {:?}",
                &expected_w_prime_ntt.polys[0].coeffs[0..4]
            );

            // This is w' that verify will compute: w - c*s2 + c*t0
            eprintln!(
                "SIGN: wcs2ct0[0][0..8] = {:?}",
                &wcs2ct0_vec.polys[0].coeffs[0..8]
            );

            // Compute what UseHint would return and compare with w1
            let mut recovered_w1 = PolyVecK::<K>::zero();
            let mut hint_idx_dbg = 0;
            for i in 0..K {
                let end = h[OMEGA + i] as usize;
                for j in 0..N {
                    let mut hint_val = 0;
                    while hint_idx_dbg < end && h[hint_idx_dbg] as usize == j {
                        hint_val = 1;
                        hint_idx_dbg += 1;
                    }
                    recovered_w1.polys[i].coeffs[j] =
                        use_hint(hint_val, wcs2ct0_vec.polys[i].coeffs[j], GAMMA2);
                }
                hint_idx_dbg = end;
            }

            // Count differences between w1 and recovered_w1
            let mut diff_count = 0;
            for i in 0..K {
                for j in 0..N {
                    if w1.polys[i].coeffs[j] != recovered_w1.polys[i].coeffs[j] {
                        diff_count += 1;
                        if diff_count <= 5 {
                            eprintln!("SIGN: MISMATCH at poly {} coeff {}: w1={}, recovered={}, wcs2ct0={}",
                                i, j, w1.polys[i].coeffs[j], recovered_w1.polys[i].coeffs[j],
                                wcs2ct0_vec.polys[i].coeffs[j]);
                        }
                    }
                }
            }
            if diff_count > 0 {
                eprintln!(
                    "SIGN: Total mismatches between w1 and UseHint(h, wcs2ct0): {}",
                    diff_count
                );
            }
        }

        if hint_count > OMEGA {
            kappa += 1;
            continue;
        }

        // Convert z to centered form for packing
        // z.reduce() puts values in [0, Q-1], but pack_z expects [-gamma1, gamma1]
        let mut z_centered = z.clone();
        for i in 0..L {
            for j in 0..N {
                let mut c = z_centered.polys[i].coeffs[j];
                if c > (Q - 1) / 2 {
                    c -= Q;
                }
                z_centered.polys[i].coeffs[j] = c;
            }
        }

        #[cfg(test)]
        {
            eprintln!(
                "SIGN: z_centered[0][0..4] = {:?}",
                &z_centered.polys[0].coeffs[0..4]
            );

            // Compute NTT(z) to compare with verify
            let mut z_for_ntt = z_centered.clone();
            z_for_ntt.ntt();
            eprintln!(
                "SIGN: NTT(z)[0].coeffs[0..4] = {:?}",
                &z_for_ntt.polys[0].coeffs[0..4]
            );

            // Verify z_hat = y_hat + c_hat ⊙ s1_hat
            let mut expected_z_hat = PolyVecL::<L>::zero();
            for i in 0..L {
                let cs1 = c_hat.pointwise_mul(&s1_hat.polys[i]);
                for j in 0..N {
                    expected_z_hat.polys[i].coeffs[j] = y_hat.polys[i].coeffs[j] + cs1.coeffs[j];
                }
            }
            expected_z_hat.reduce();
            eprintln!(
                "SIGN: expected z_hat = y_hat + c_hat⊙s1_hat: [0][0..4] = {:?}",
                &expected_z_hat.polys[0].coeffs[0..4]
            );

            // Check if they match
            let match_first4 = (0..4).all(|j| {
                freeze(z_for_ntt.polys[0].coeffs[j]) == freeze(expected_z_hat.polys[0].coeffs[j])
            });
            eprintln!("SIGN: z_hat matches expected? (first 4): {}", match_first4);

            eprintln!("SIGN: hint_counts = {:?}", &h[OMEGA..OMEGA + K]);
            eprintln!(
                "SIGN: first 10 hint positions = {:?}",
                &h[0..10.min(hint_count)]
            );
        }

        // Encode signature: c_tilde || z || h
        let sig_size = C_TILDE_BYTES + L * z_bytes + OMEGA + K;
        let mut sig = Vec::with_capacity(sig_size);

        sig.extend_from_slice(c_tilde);

        for i in 0..L {
            let mut buf = vec![0u8; z_bytes];
            if gamma1_bits == 17 {
                pack_z_17(&z_centered.polys[i], &mut buf);
            } else {
                pack_z_19(&z_centered.polys[i], &mut buf);
            }
            sig.extend_from_slice(&buf);
        }

        sig.extend_from_slice(&h[..OMEGA + K]);

        // Zeroize sensitive intermediate values before returning
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

    // Parse signature - c_tilde has variable length based on security level
    let c_tilde = &sig[0..C_TILDE_BYTES];

    let mut z = PolyVecL::<L>::zero();
    for i in 0..L {
        let offset = C_TILDE_BYTES + i * z_bytes;
        if gamma1_bits == 17 {
            unpack_z_17(&sig[offset..offset + z_bytes], &mut z.polys[i]);
        } else {
            unpack_z_19(&sig[offset..offset + z_bytes], &mut z.polys[i]);
        }
    }

    // Parse hints
    let h_start = C_TILDE_BYTES + L * z_bytes;
    let h = &sig[h_start..];

    // Check z norm
    if !z.check_norm(GAMMA1 - BETA) {
        return false;
    }

    // Check hint count and validate hint positions are strictly increasing
    // per FIPS 204 canonical encoding requirements
    let mut hint_count = 0;
    for i in 0..K {
        let start = if i == 0 { 0 } else { h[OMEGA + i - 1] as usize };
        let end = h[OMEGA + i] as usize;

        // End must be within bounds and monotonically increasing
        if end > OMEGA || end < start {
            return false;
        }

        // Validate hint positions are strictly increasing within this polynomial
        let mut prev_pos: Option<u8> = None;
        for idx in start..end {
            let pos = h[idx];
            // Position must be < N (256)
            if pos as usize >= N {
                return false;
            }
            // Positions must be strictly increasing (canonical encoding)
            if let Some(p) = prev_pos {
                if pos <= p {
                    return false;
                }
            }
            prev_pos = Some(pos);
        }

        hint_count = end;
    }
    if hint_count > OMEGA {
        return false;
    }

    // Verify unused hint slots are zero (canonical encoding per FIPS 204)
    // This prevents signature malleability where non-zero padding would be ignored
    for i in hint_count..OMEGA {
        if h[i] != 0 {
            return false;
        }
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

    #[cfg(test)]
    {
        eprintln!("VERIFY: z[0][0..4] = {:?}", &z.polys[0].coeffs[0..4]);
        eprintln!("VERIFY: t1[0][0..4] = {:?}", &t1.polys[0].coeffs[0..4]);
        eprintln!(
            "VERIFY: t1_scaled[0][0..4] = {:?}",
            &t1_scaled.polys[0].coeffs[0..4]
        );
    }

    t1_scaled.ntt();

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: A[0][0].coeffs[0..4] = {:?}",
            &a.rows[0].polys[0].coeffs[0..4]
        );
        eprintln!(
            "VERIFY: z_hat[0].coeffs[0..4] = {:?}",
            &z_hat.polys[0].coeffs[0..4]
        );
    }

    // Compute A*z - c*(t1*2^d) in NTT domain
    let mut az = a.mul_vec(&z_hat);
    az.reduce(); // Reduce immediately after accumulation, like in sign

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: az[0].coeffs[0..4] = {:?}",
            &az.polys[0].coeffs[0..4]
        );
    }

    let mut ct1_2d = PolyVecK::<K>::zero();
    for i in 0..K {
        ct1_2d.polys[i] = c_hat.pointwise_mul(&t1_scaled.polys[i]);
    }
    ct1_2d.reduce(); // Reduce after pointwise multiplication

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: ct1_2d[0].coeffs[0..4] = {:?}",
            &ct1_2d.polys[0].coeffs[0..4]
        );
    }

    // w' = A*z - c*t1*2^d (in NTT domain)
    let mut w_prime_hat = PolyVecK::<K>::zero();
    for i in 0..K {
        for j in 0..N {
            w_prime_hat.polys[i].coeffs[j] = az.polys[i].coeffs[j] - ct1_2d.polys[i].coeffs[j];
        }
    }

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: w'_hat[0].coeffs[0..4] (before reduce) = {:?}",
            &w_prime_hat.polys[0].coeffs[0..4]
        );
    }

    w_prime_hat.reduce();

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: w'_hat[0].coeffs[0..4] (after reduce) = {:?}",
            &w_prime_hat.polys[0].coeffs[0..4]
        );
        eprintln!("VERIFY: compare with SIGN expected_w'_ntt values above");
    }

    w_prime_hat.inv_ntt();
    w_prime_hat.caddq();

    let w_prime = w_prime_hat;

    #[cfg(test)]
    {
        eprintln!("VERIFY: hint_counts = {:?}", &h[OMEGA..]);
        eprintln!(
            "VERIFY: first 10 hint positions = {:?}",
            &h[0..10.min(h[OMEGA + K - 1] as usize)]
        );
    }

    // Apply hints to get w'1
    let mut w1_prime = PolyVecK::<K>::zero();
    let mut hint_idx = 0;
    for i in 0..K {
        let end = h[OMEGA + i] as usize;
        for j in 0..N {
            let mut hint_val = 0;
            while hint_idx < end && h[hint_idx] as usize == j {
                hint_val = 1;
                hint_idx += 1;
            }
            w1_prime.polys[i].coeffs[j] =
                use_hint(hint_val, freeze(w_prime.polys[i].coeffs[j]), GAMMA2);
        }
        hint_idx = end;
    }

    #[cfg(test)]
    {
        eprintln!(
            "VERIFY: w_prime[0][0..8] = {:?}",
            &w_prime.polys[0].coeffs[0..8]
        );
        eprintln!(
            "VERIFY: w_prime[0][12..20] = {:?}",
            &w_prime.polys[0].coeffs[12..20]
        );
        eprintln!(
            "VERIFY: w1_prime[0][12..20] = {:?}",
            &w1_prime.polys[0].coeffs[12..20]
        );
    }

    // Encode w'1
    let w1_bytes = if GAMMA2 == 261888 { 128 } else { 192 };
    let mut w1_encoded = vec![0u8; K * w1_bytes];
    for i in 0..K {
        pack_w1(
            &w1_prime.polys[i],
            GAMMA2,
            &mut w1_encoded[i * w1_bytes..(i + 1) * w1_bytes],
        );
    }

    #[cfg(test)]
    {
        // Print per-polynomial checksums
        for i in 0..K {
            let start = i * w1_bytes;
            let poly_checksum: u64 = w1_encoded[start..start + w1_bytes]
                .iter()
                .map(|&b| b as u64)
                .sum();
            eprintln!("VERIFY: w1_prime[{}] checksum = {}", i, poly_checksum);
        }
    }

    // c_tilde' = H(mu || w1Encode(w'1))
    let mut c_tilde_prime = [0u8; 64];
    h2(&mu, &w1_encoded, &mut c_tilde_prime);

    // Verify c_tilde == c_tilde'
    #[cfg(test)]
    {
        eprintln!("c_tilde:       {:?}", &c_tilde[..8]);
        eprintln!("c_tilde_prime: {:?}", &c_tilde_prime[..8]);
        eprintln!("Match: {}", c_tilde == &c_tilde_prime[..C_TILDE_BYTES]);
    }
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
}
