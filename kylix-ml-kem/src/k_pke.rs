//! K-PKE: IND-CPA-secure public-key encryption (FIPS 203 Algorithms 13-15).
//!
//! This module implements the underlying PKE scheme that ML-KEM builds upon.
//! K-PKE provides IND-CPA security but not IND-CCA2 security; the full ML-KEM
//! construction adds CCA security through the Fujisaki-Okamoto transform.

#![allow(dead_code)]

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encode::{msg_to_poly, poly_to_msg};
use crate::hash::{hash_g, prf};
use crate::matrix::{matrix_vec_mul, sample_matrix};
use crate::ntt::inv_ntt;
use crate::params::common::N;
use crate::poly::{
    poly_cbd, poly_compress, poly_decompress, poly_from_mont, poly_reduce, poly_to_mont, Poly,
};
use crate::polyvec::PolyVec;

/// K-PKE Key Generation (FIPS 203 Algorithm 13).
///
/// Generates an encryption key pair for the K-PKE scheme.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `ETA1` - Noise parameter for s and e (2 or 3)
///
/// # Arguments
/// * `d` - 32-byte random seed
///
/// # Returns
/// * `ek_pke` - Encryption key (K*384 + 32 bytes)
/// * `dk_pke` - Decryption key (K*384 bytes)
///
/// # Algorithm
/// 1. (rho, sigma) = G(d)
/// 2. Sample matrix A from rho
/// 3. Sample s and e from sigma using CBD
/// 4. Compute t = As + e in NTT domain
/// 5. ek_pke = encode(t) || rho
/// 6. dk_pke = encode(s)
pub fn k_pke_keygen<const K: usize, const ETA1: usize>(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    // 1. (rho, sigma) = G(d)
    let g_output = hash_g(d);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_output[..32]);
    sigma.copy_from_slice(&g_output[32..]);

    // 2. Sample matrix A from rho (in NTT domain)
    let a: [[Poly; K]; K] = sample_matrix(&rho, false);

    // 3. Sample s from sigma using CBD with eta1
    let mut s: PolyVec<K> = PolyVec::new();
    let prf_output_len = 64 * ETA1;
    for i in 0..K {
        let mut prf_output = vec![0u8; prf_output_len];
        prf(&sigma, i as u8, &mut prf_output);
        s.polys[i] = poly_cbd(ETA1, &prf_output);
    }

    // 4. Sample e from sigma using CBD with eta1
    let mut e: PolyVec<K> = PolyVec::new();
    for i in 0..K {
        let mut prf_output = vec![0u8; prf_output_len];
        prf(&sigma, (K + i) as u8, &mut prf_output);
        e.polys[i] = poly_cbd(ETA1, &prf_output);
    }

    // 5. Convert s and e to NTT domain
    s.ntt();
    e.ntt();

    // 6. Compute t = A*s + e in NTT domain
    let mut t = matrix_vec_mul(&a, &s);
    t.to_mont(); // Undo R^-1 scaling from basemul
    t.add_assign(&e);
    t.reduce_full(); // Reduce to canonical form [0, q-1] for encoding

    // 7. Encode outputs
    // ek_pke = encode(t) || rho
    let t_bytes = t.to_bytes();
    let mut ek_pke = Vec::with_capacity(K * 384 + 32);
    ek_pke.extend_from_slice(&t_bytes);
    ek_pke.extend_from_slice(&rho);

    // dk_pke = encode(s)
    s.reduce_full(); // Reduce to canonical form [0, q-1] for encoding (s is already in normal form after NTT)
    let dk_pke = s.to_bytes();

    (ek_pke, dk_pke)
}

/// K-PKE Encryption (FIPS 203 Algorithm 14).
///
/// Encrypts a message using the K-PKE scheme.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `ETA1` - Noise parameter for r (2 or 3)
/// * `ETA2` - Noise parameter for e1 and e2 (always 2)
/// * `DU` - Compression parameter for u (10 or 11)
/// * `DV` - Compression parameter for v (4 or 5)
///
/// # Arguments
/// * `ek_pke` - Encryption key
/// * `m` - 32-byte message to encrypt
/// * `r` - 32-byte randomness (deterministic encryption with given r)
///
/// # Returns
/// Ciphertext bytes (c1 || c2)
///
/// # Algorithm
/// 1. Parse ek_pke as (t, rho)
/// 2. Sample A^T from rho
/// 3. Sample r_vec, e1, e2 from r using CBD
/// 4. Compute u = A^T * r_vec + e1
/// 5. Compute v = t^T * r_vec + e2 + encode(m)
/// 6. c1 = Compress_du(u), c2 = Compress_dv(v)
/// 7. return c1 || c2
pub fn k_pke_encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek_pke: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
) -> Vec<u8> {
    // 1. Parse ek_pke as (t, rho)
    let t_bytes = &ek_pke[..K * 384];
    let rho: &[u8; 32] = ek_pke[K * 384..K * 384 + 32].try_into().unwrap();

    let t: PolyVec<K> = PolyVec::from_bytes(t_bytes);

    // 2. Sample A^T from rho (transpose=true)
    let a_t: [[Poly; K]; K] = sample_matrix(rho, true);

    // 3. Sample r_vec from r using CBD with eta1
    let mut r_vec: PolyVec<K> = PolyVec::new();
    let prf_output_len1 = 64 * ETA1;
    for i in 0..K {
        let mut prf_output = vec![0u8; prf_output_len1];
        prf(r, i as u8, &mut prf_output);
        r_vec.polys[i] = poly_cbd(ETA1, &prf_output);
    }

    // 4. Sample e1 from r using CBD with eta2
    let mut e1: PolyVec<K> = PolyVec::new();
    let prf_output_len2 = 64 * ETA2;
    for i in 0..K {
        let mut prf_output = vec![0u8; prf_output_len2];
        prf(r, (K + i) as u8, &mut prf_output);
        e1.polys[i] = poly_cbd(ETA2, &prf_output);
    }

    // 5. Sample e2 from r using CBD with eta2
    let mut e2_prf_output = vec![0u8; prf_output_len2];
    prf(r, (2 * K) as u8, &mut e2_prf_output);
    let e2 = poly_cbd(ETA2, &e2_prf_output);

    // 6. Convert r_vec to NTT domain
    r_vec.ntt();

    // 7. Compute u = NTT^-1(A^T * r_vec) + e1
    // A^T is normal form (sampled), r_vec has NTT form
    // After basemul, call to_mont to compensate for R^-1
    // After inv_ntt, call from_mont to convert from Montgomery form back to normal form
    let mut u = matrix_vec_mul(&a_t, &r_vec);
    u.to_mont(); // Compensate for R^-1 from basemul
    u.inv_ntt();
    u.from_mont(); // Convert from Montgomery form back to normal form
    u.add_assign(&e1);
    u.reduce();

    // 8. Compute v = NTT^-1(t^T * r_vec) + e2 + mu
    // After basemul, call to_mont to compensate for R^-1
    // After inv_ntt, call from_mont to convert from Montgomery form back to normal form
    let mut v = t.inner_product(&r_vec);
    poly_to_mont(&mut v); // Compensate for R^-1 from basemul
    inv_ntt(&mut v);
    poly_from_mont(&mut v); // Convert from Montgomery form back to normal form
    poly_reduce(&mut v);

    // Add e2
    for i in 0..N {
        v.coeffs[i] = v.coeffs[i].wrapping_add(e2.coeffs[i]);
    }

    // Add message encoding
    let mu = msg_to_poly(m);
    for i in 0..N {
        v.coeffs[i] = v.coeffs[i].wrapping_add(mu.coeffs[i]);
    }
    poly_reduce(&mut v);

    // 9. Compress u and v
    let c1 = u.compress(DU);
    let mut c2 = vec![0u8; 32 * DV];
    poly_compress(&v, DV as u32, &mut c2);

    // 10. Return c1 || c2
    let mut ciphertext = Vec::with_capacity(c1.len() + c2.len());
    ciphertext.extend_from_slice(&c1);
    ciphertext.extend_from_slice(&c2);

    ciphertext
}

/// K-PKE Decryption (FIPS 203 Algorithm 15).
///
/// Decrypts a ciphertext using the K-PKE scheme.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `DU` - Compression parameter for u (10 or 11)
/// * `DV` - Compression parameter for v (4 or 5)
///
/// # Arguments
/// * `dk_pke` - Decryption key
/// * `c` - Ciphertext bytes
///
/// # Returns
/// 32-byte decrypted message
///
/// # Algorithm
/// 1. Parse c as (c1, c2)
/// 2. u = Decompress_du(c1)
/// 3. v = Decompress_dv(c2)
/// 4. s = decode(dk_pke)
/// 5. w = v - NTT^-1(s^T * NTT(u))
/// 6. m = Compress_1(w)
pub fn k_pke_decrypt<const K: usize, const DU: usize, const DV: usize>(
    dk_pke: &[u8],
    c: &[u8],
) -> [u8; 32] {
    // 1. Parse ciphertext as (c1, c2)
    let c1_len = K * 32 * DU;
    let c1 = &c[..c1_len];
    let c2 = &c[c1_len..];

    // 2. Decompress u from c1
    let mut u: PolyVec<K> = PolyVec::decompress(c1, DU);

    // 3. Decompress v from c2
    let v = poly_decompress(c2, DV as u32);

    // 4. Decode secret key s
    let s: PolyVec<K> = PolyVec::from_bytes(dk_pke);

    // 5. Compute w = v - NTT^-1(s^T * NTT(u))
    // After basemul, call to_mont to compensate for R^-1
    // After inv_ntt, call from_mont to convert from Montgomery form back to normal form
    u.ntt();
    let mut s_t_u = s.inner_product(&u);
    poly_to_mont(&mut s_t_u); // Compensate for R^-1 from basemul
    inv_ntt(&mut s_t_u);
    poly_from_mont(&mut s_t_u); // Convert from Montgomery form back to normal form
    poly_reduce(&mut s_t_u);

    // w = v - s_t_u
    let mut w = Poly::new();
    for i in 0..N {
        w.coeffs[i] = v.coeffs[i].wrapping_sub(s_t_u.coeffs[i]);
    }
    poly_reduce(&mut w);

    // 6. Compress w to 1-bit coefficients to get message
    poly_to_msg(&w)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test with ML-KEM-512 parameters
    const K512: usize = 2;
    const ETA1_512: usize = 3;
    const ETA2_512: usize = 2;
    const DU_512: usize = 10;
    const DV_512: usize = 4;

    // Test with ML-KEM-768 parameters
    const K768: usize = 3;
    const ETA1_768: usize = 2;
    const ETA2_768: usize = 2;
    const DU_768: usize = 10;
    const DV_768: usize = 4;

    #[test]
    fn test_k_pke_keygen_deterministic() {
        let d = [0x42u8; 32];
        let (ek1, dk1) = k_pke_keygen::<K768, ETA1_768>(&d);
        let (ek2, dk2) = k_pke_keygen::<K768, ETA1_768>(&d);
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn test_k_pke_keygen_key_sizes_768() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke_keygen::<K768, ETA1_768>(&d);
        assert_eq!(ek.len(), K768 * 384 + 32); // 1184 bytes
        assert_eq!(dk.len(), K768 * 384); // 1152 bytes
    }

    #[test]
    fn test_k_pke_keygen_key_sizes_512() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke_keygen::<K512, ETA1_512>(&d);
        assert_eq!(ek.len(), K512 * 384 + 32); // 800 bytes
        assert_eq!(dk.len(), K512 * 384); // 768 bytes
    }

    #[test]
    fn test_k_pke_encrypt_decrypt_roundtrip_768() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke_keygen::<K768, ETA1_768>(&d);

        let msg = [0x55u8; 32];
        let r = [0xAAu8; 32];

        let ciphertext = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r);
        let decrypted = k_pke_decrypt::<K768, DU_768, DV_768>(&dk, &ciphertext);

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_k_pke_encrypt_decrypt_roundtrip_512() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke_keygen::<K512, ETA1_512>(&d);

        let msg = [0x55u8; 32];
        let r = [0xAAu8; 32];

        let ciphertext = k_pke_encrypt::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&ek, &msg, &r);
        let decrypted = k_pke_decrypt::<K512, DU_512, DV_512>(&dk, &ciphertext);

        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_k_pke_encrypt_deterministic() {
        let d = [0x42u8; 32];
        let (ek, _) = k_pke_keygen::<K768, ETA1_768>(&d);

        let msg = [0x55u8; 32];
        let r = [0xAAu8; 32];

        let ct1 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r);
        let ct2 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r);

        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_k_pke_ciphertext_size_768() {
        let d = [0x42u8; 32];
        let (ek, _) = k_pke_keygen::<K768, ETA1_768>(&d);

        let msg = [0x55u8; 32];
        let r = [0xAAu8; 32];

        let ciphertext = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r);

        // c1 = K * 32 * DU = 3 * 32 * 10 = 960 bytes
        // c2 = 32 * DV = 32 * 4 = 128 bytes
        // total = 1088 bytes
        assert_eq!(ciphertext.len(), K768 * 32 * DU_768 + 32 * DV_768);
    }

    #[test]
    fn test_k_pke_different_messages() {
        let d = [0x42u8; 32];
        let (ek, dk) = k_pke_keygen::<K768, ETA1_768>(&d);

        let r = [0xAAu8; 32];

        // Test with all zeros
        let msg1 = [0x00u8; 32];
        let ct1 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg1, &r);
        let dec1 = k_pke_decrypt::<K768, DU_768, DV_768>(&dk, &ct1);
        assert_eq!(msg1, dec1);

        // Test with all ones
        let msg2 = [0xFFu8; 32];
        let ct2 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg2, &r);
        let dec2 = k_pke_decrypt::<K768, DU_768, DV_768>(&dk, &ct2);
        assert_eq!(msg2, dec2);

        // Ciphertexts should be different
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_k_pke_different_randomness() {
        let d = [0x42u8; 32];
        let (ek, _) = k_pke_keygen::<K768, ETA1_768>(&d);

        let msg = [0x55u8; 32];
        let r1 = [0xAAu8; 32];
        let r2 = [0xBBu8; 32];

        let ct1 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r1);
        let ct2 = k_pke_encrypt::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &msg, &r2);

        // Different randomness should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }
}
