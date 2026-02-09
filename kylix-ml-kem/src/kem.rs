//! ML-KEM Key Encapsulation Mechanism (FIPS 203 Algorithms 16-18).
//!
//! This module implements the full ML-KEM scheme with IND-CCA2 security.
//! ML-KEM uses the Fujisaki-Okamoto transform to build a CCA-secure KEM
//! from the underlying IND-CPA secure K-PKE scheme.

// Internal implementation functions; public API is exposed via variant modules.
#![allow(dead_code)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encode::check_ek_modulus;
use crate::hash::{hash_g, hash_h, hash_j};
use crate::k_pke::{k_pke_decrypt, k_pke_encrypt, k_pke_keygen};
use kylix_core::{Error, Result};
use subtle::{ConditionallySelectable, ConstantTimeEq};

/// ML-KEM Key Generation (FIPS 203 Algorithm 16).
///
/// Generates a key pair for the ML-KEM scheme.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `ETA1` - Noise parameter (2 or 3)
///
/// # Arguments
/// * `d` - 32-byte random seed for K-PKE key generation
/// * `z` - 32-byte random seed for implicit rejection
///
/// # Returns
/// * `dk` - Decapsulation key (dk_pke || ek || H(ek) || z)
/// * `ek` - Encapsulation key (same as ek_pke)
///
/// # Key Sizes
/// - dk: K*384 + K*384 + 32 + 32 + 32 bytes
/// - ek: K*384 + 32 bytes
pub fn ml_kem_keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    // 1. Generate K-PKE key pair
    let (ek, dk_pke) = k_pke_keygen::<K, ETA1>(d);

    // 2. H(ek)
    let h_ek = hash_h(&ek);

    // 3. dk = dk_pke || ek || H(ek) || z
    let dk_pke_size = K * 384;
    let ek_size = K * 384 + 32;
    let dk_size = dk_pke_size + ek_size + 32 + 32;

    let mut dk = Vec::with_capacity(dk_size);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    (dk, ek)
}

/// ML-KEM Encapsulation (FIPS 203 Algorithm 17).
///
/// Encapsulates a shared secret using the encapsulation key.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `ETA1` - Noise parameter for encryption (2 or 3)
/// * `ETA2` - Noise parameter for encryption (always 2)
/// * `DU` - Compression parameter for u (10 or 11)
/// * `DV` - Compression parameter for v (4 or 5)
///
/// # Arguments
/// * `ek` - Encapsulation key
/// * `m` - 32-byte random message
///
/// # Returns
/// On success, returns `Ok((c, shared_secret))` where:
/// * `c` - Ciphertext
/// * `shared_secret` - 32-byte shared secret
///
/// # Errors
/// - [`Error::InvalidKeyLength`] if `ek` length is not `K * 384 + 32`.
/// - [`Error::EncodingError`] if any decoded 12-bit coefficient in `ek` is `>= q` (FIPS 203 §7.2 modulus check).
///
/// # Algorithm
/// 1. h = H(ek)
/// 2. (K, r) = G(m || h)
/// 3. c = K-PKE.Encrypt(ek, m, r)
/// 4. return (c, K)
pub fn ml_kem_encaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32])> {
    let expected_ek_size = K * 384 + 32;
    if ek.len() != expected_ek_size {
        return Err(Error::InvalidKeyLength {
            expected: expected_ek_size,
            actual: ek.len(),
        });
    }

    // FIPS 203 §7.2: Modulus check — verify all ek coefficients are in [0, q-1]
    if !check_ek_modulus(ek) {
        return Err(Error::EncodingError);
    }

    // 1. h = H(ek)
    let h = hash_h(ek);

    // 2. (K, r) = G(m || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h);
    let g_output = hash_g(&g_input);

    let mut shared_secret = [0u8; 32];
    let mut r = [0u8; 32];
    shared_secret.copy_from_slice(&g_output[..32]);
    r.copy_from_slice(&g_output[32..]);

    // 3. c = K-PKE.Encrypt(ek, m, r)
    let c = k_pke_encrypt::<K, ETA1, ETA2, DU, DV>(ek, m, &r);

    Ok((c, shared_secret))
}

/// ML-KEM Decapsulation (FIPS 203 Algorithm 18).
///
/// Decapsulates the shared secret from a ciphertext using the decapsulation key.
/// Uses implicit rejection for CCA security.
///
/// # Type Parameters
/// * `K` - Module rank (2, 3, or 4)
/// * `ETA1` - Noise parameter for encryption (2 or 3)
/// * `ETA2` - Noise parameter for encryption (always 2)
/// * `DU` - Compression parameter for u (10 or 11)
/// * `DV` - Compression parameter for v (4 or 5)
///
/// # Arguments
/// * `dk` - Decapsulation key
/// * `c` - Ciphertext
///
/// # Returns
/// On success, returns `Ok(shared_secret)` — the 32-byte shared secret.
///
/// # Errors
/// - [`Error::InvalidKeyLength`] if `dk` length is not `K * 768 + 96`
/// - [`Error::InvalidCiphertextLength`] if `c` length is not `32 * (K * DU + DV)`
///
/// # Algorithm (with implicit rejection)
/// 1. Parse dk as (dk_pke || ek || h || z)
/// 2. m' = K-PKE.Decrypt(dk_pke, c)
/// 3. (K', r') = G(m' || h)
/// 4. c' = K-PKE.Encrypt(ek, m', r')
/// 5. K_bar = J(z || c)  -- implicit rejection key
/// 6. if c == c': return K' else: return K_bar (constant-time)
pub fn ml_kem_decaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    dk: &[u8],
    c: &[u8],
) -> Result<[u8; 32]> {
    // Parse dk = dk_pke || ek || h || z
    let dk_pke_size = K * 384;
    let ek_size = K * 384 + 32;
    let expected_dk_size = dk_pke_size + ek_size + 32 + 32;

    if dk.len() != expected_dk_size {
        return Err(Error::InvalidKeyLength {
            expected: expected_dk_size,
            actual: dk.len(),
        });
    }

    let expected_c_size = 32 * (K * DU + DV);
    if c.len() != expected_c_size {
        return Err(Error::InvalidCiphertextLength {
            expected: expected_c_size,
            actual: c.len(),
        });
    }

    let (dk_pke, rest) = dk.split_at(dk_pke_size);
    let (ek, rest) = rest.split_at(ek_size);
    let (h_bytes, z_bytes) = rest.split_at(32);

    debug_assert_eq!(h_bytes.len(), 32);
    debug_assert_eq!(z_bytes.len(), 32);
    let h: &[u8; 32] = h_bytes
        .try_into()
        .expect("infallible: h_bytes is 32 bytes after dk length check");
    let z: &[u8; 32] = z_bytes
        .try_into()
        .expect("infallible: z_bytes is 32 bytes after dk length check");

    // 1. m' = K-PKE.Decrypt(dk_pke, c)
    let m_prime = k_pke_decrypt::<K, DU, DV>(dk_pke, c);

    // 2. (K', r') = G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(h);
    let g_output = hash_g(&g_input);

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_output[..32]);
    r_prime.copy_from_slice(&g_output[32..]);

    // 3. c' = K-PKE.Encrypt(ek, m', r')
    let c_prime = k_pke_encrypt::<K, ETA1, ETA2, DU, DV>(ek, &m_prime, &r_prime);

    // 4. K_bar = J(z || c)
    let mut k_bar = [0u8; 32];
    hash_j(z, c, &mut k_bar);

    // 5. Constant-time comparison and selection
    // If c == c': return K', else return K_bar
    let ciphertexts_equal = c.ct_eq(&c_prime);

    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = u8::conditional_select(&k_bar[i], &k_prime[i], ciphertexts_equal);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ML-KEM-512 parameters
    const K512: usize = 2;
    const ETA1_512: usize = 3;
    const ETA2_512: usize = 2;
    const DU_512: usize = 10;
    const DV_512: usize = 4;

    // ML-KEM-768 parameters
    const K768: usize = 3;
    const ETA1_768: usize = 2;
    const ETA2_768: usize = 2;
    const DU_768: usize = 10;
    const DV_768: usize = 4;

    // ML-KEM-1024 parameters
    const K1024: usize = 4;
    const ETA1_1024: usize = 2;
    const ETA2_1024: usize = 2;
    const DU_1024: usize = 11;
    const DV_1024: usize = 5;

    #[test]
    fn test_ml_kem_keygen_deterministic() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let (dk1, ek1) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (dk2, ek2) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        assert_eq!(dk1, dk2);
        assert_eq!(ek1, ek2);
    }

    #[test]
    fn test_ml_kem_key_sizes_512() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let (dk, ek) = ml_kem_keygen::<K512, ETA1_512>(&d, &z);
        // dk = dk_pke (768) + ek (800) + H(ek) (32) + z (32) = 1632
        assert_eq!(dk.len(), 1632);
        // ek = t (768) + rho (32) = 800
        assert_eq!(ek.len(), 800);
    }

    #[test]
    fn test_ml_kem_key_sizes_768() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let (dk, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        // dk = dk_pke (1152) + ek (1184) + H(ek) (32) + z (32) = 2400
        assert_eq!(dk.len(), 2400);
        // ek = t (1152) + rho (32) = 1184
        assert_eq!(ek.len(), 1184);
    }

    #[test]
    fn test_ml_kem_key_sizes_1024() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let (dk, ek) = ml_kem_keygen::<K1024, ETA1_1024>(&d, &z);
        // dk = dk_pke (1536) + ek (1568) + H(ek) (32) + z (32) = 3168
        assert_eq!(dk.len(), 3168);
        // ek = t (1536) + rho (32) = 1568
        assert_eq!(ek.len(), 1568);
    }

    #[test]
    fn test_ml_kem_roundtrip_512() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (dk, ek) = ml_kem_keygen::<K512, ETA1_512>(&d, &z);
        let (c, ss1) = ml_kem_encaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&ek, &m).unwrap();
        let ss2 = ml_kem_decaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&dk, &c).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_roundtrip_768() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (dk, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (c, ss1) = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m).unwrap();
        let ss2 = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &c).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_roundtrip_1024() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (dk, ek) = ml_kem_keygen::<K1024, ETA1_1024>(&d, &z);
        let (c, ss1) =
            ml_kem_encaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&ek, &m).unwrap();
        let ss2 = ml_kem_decaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&dk, &c).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_ciphertext_sizes() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        // ML-KEM-512: c1 = 640, c2 = 128, total = 768
        let (_, ek512) = ml_kem_keygen::<K512, ETA1_512>(&d, &z);
        let (c512, _) =
            ml_kem_encaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&ek512, &m).unwrap();
        assert_eq!(c512.len(), 768);

        // ML-KEM-768: c1 = 960, c2 = 128, total = 1088
        let (_, ek768) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (c768, _) =
            ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek768, &m).unwrap();
        assert_eq!(c768.len(), 1088);

        // ML-KEM-1024: c1 = 1408, c2 = 160, total = 1568
        let (_, ek1024) = ml_kem_keygen::<K1024, ETA1_1024>(&d, &z);
        let (c1024, _) =
            ml_kem_encaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&ek1024, &m).unwrap();
        assert_eq!(c1024.len(), 1568);
    }

    #[test]
    fn test_ml_kem_implicit_rejection() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (dk, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (mut c, ss1) =
            ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m).unwrap();

        // Corrupt the ciphertext
        c[0] ^= 0xFF;

        // Decapsulation should still succeed but return a different key
        let ss2 = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &c).unwrap();

        // The shared secrets should be different
        assert_ne!(ss1, ss2);

        // The "bad" shared secret should still be deterministic
        let ss3 = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &c).unwrap();
        assert_eq!(ss2, ss3);
    }

    #[test]
    fn test_ml_kem_encaps_deterministic() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (_, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (c1, ss1) = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m).unwrap();
        let (c2, ss2) = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_different_messages() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];

        let (dk, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);

        let m1 = [0x00u8; 32];
        let m2 = [0xFFu8; 32];

        let (c1, ss1) =
            ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m1).unwrap();
        let (c2, ss2) =
            ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m2).unwrap();

        // Different messages should produce different ciphertexts and shared secrets
        assert_ne!(c1, c2);
        assert_ne!(ss1, ss2);

        // But decapsulation should recover the correct shared secrets
        let dec_ss1 = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &c1).unwrap();
        let dec_ss2 = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &c2).unwrap();

        assert_eq!(ss1, dec_ss1);
        assert_eq!(ss2, dec_ss2);
    }

    #[test]
    fn test_ml_kem_encaps_invalid_ek_length() {
        let m = [0x55u8; 32];
        let expected_ek_len = K768 * 384 + 32;

        // Too short
        let short_ek = vec![0u8; 100];
        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&short_ek, &m);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_ek_len && actual == 100
        ));

        // Too long
        let long_ek = vec![0u8; 2000];
        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&long_ek, &m);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_ek_len && actual == 2000
        ));

        // Empty
        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&[], &m);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_ek_len && actual == 0
        ));
    }

    #[test]
    fn test_ml_kem_decaps_invalid_dk_length() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];
        let expected_dk_len = K768 * 768 + 96;
        let expected_ct_len = 32 * (K768 * DU_768 + DV_768);

        let (dk, ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);
        let (c, _) = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m).unwrap();

        // Too short dk
        let short_dk = vec![0u8; 100];
        let result = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&short_dk, &c);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_dk_len && actual == 100
        ));

        // Empty dk
        let result = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&[], &c);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_dk_len && actual == 0
        ));

        // Invalid ciphertext length
        let result = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &[0u8; 100]);
        assert!(matches!(
            result,
            Err(Error::InvalidCiphertextLength { expected, actual })
                if expected == expected_ct_len && actual == 100
        ));

        // Empty ciphertext
        let result = ml_kem_decaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&dk, &[]);
        assert!(matches!(
            result,
            Err(Error::InvalidCiphertextLength { expected, actual })
                if expected == expected_ct_len && actual == 0
        ));
    }

    #[test]
    fn test_ml_kem_encaps_invalid_ek_coefficient() {
        let d = [0x42u8; 32];
        let z = [0x43u8; 32];
        let m = [0x55u8; 32];

        let (_, original_ek) = ml_kem_keygen::<K768, ETA1_768>(&d, &z);

        // Test with coefficient = Q (3329)
        let mut ek = original_ek.clone();
        // Set a 12-bit coefficient to Q (3329) — invalid
        // Bytes [0..3] encode two 12-bit coefficients:
        //   c0 = b0 | ((b1 & 0x0F) << 8)
        //   c1 = (b1 >> 4) | (b2 << 4)
        // Set c0 = 3329 = 0xD01: b0 = 0x01, b1 low nibble = 0x0D
        let b1_high = ek[1] & 0xF0;
        ek[0] = 0x01;
        ek[1] = b1_high | 0x0D;

        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m);
        assert!(matches!(result, Err(Error::EncodingError)));

        // Also test with coefficient = 0xFFF (4095)
        let mut ek2 = original_ek;
        // Set c0 = 0xFFF: b0 = 0xFF, b1 low nibble = 0x0F
        let b1_high = ek2[1] & 0xF0;
        ek2[0] = 0xFF;
        ek2[1] = b1_high | 0x0F;

        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek2, &m);
        assert!(matches!(result, Err(Error::EncodingError)));
    }

    #[test]
    fn test_ml_kem_encaps_valid_ek_max_coefficient() {
        let m = [0x55u8; 32];
        let ek_size = K768 * 384 + 32;
        let t_size = K768 * 384;

        // Craft an ek where all coefficients are Q-1 (3328 = 0xD00)
        // c0 = 0xD00: b0 = 0x00, b1 low = 0x0D
        // c1 = 0xD00: b1 high = 0x00, b2 = 0x0D0 >> 4... let's compute:
        // c1 = (b1 >> 4) | (b2 << 4) = 0xD00
        // b1 >> 4 = 0x00 (since b1 = 0x0D, b1 >> 4 = 0x00)
        // b2 << 4 must give remaining: 0xD00 = (0x00) | (b2 << 4) => b2 = 0xD0
        // Wait, recalc: b1 = 0x0D, b1 >> 4 = 0, b2 << 4 = 0xD00 => b2 = 0xD0
        let mut ek = vec![0u8; ek_size];
        for chunk in ek[..t_size].chunks_exact_mut(3) {
            chunk[0] = 0x00;
            chunk[1] = 0x0D;
            chunk[2] = 0xD0;
        }
        // rho can be anything
        for b in &mut ek[t_size..] {
            *b = 0xAA;
        }

        // Should pass the modulus check (all coefficients = Q-1 = 3328 < Q)
        let result = ml_kem_encaps::<K768, ETA1_768, ETA2_768, DU_768, DV_768>(&ek, &m);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ml_kem_validation_all_variants() {
        let m = [0x55u8; 32];

        // ML-KEM-512
        let expected_ek_512 = K512 * 384 + 32;
        let result = ml_kem_encaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&[0u8; 1], &m);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_ek_512 && actual == 1
        ));

        // ML-KEM-1024
        let expected_ek_1024 = K1024 * 384 + 32;
        let result = ml_kem_encaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&[0u8; 1], &m);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_ek_1024 && actual == 1
        ));

        // ML-KEM-512 decaps: invalid dk
        let expected_dk_512 = K512 * 768 + 96;
        let expected_ct_512 = 32 * (K512 * DU_512 + DV_512);
        let result = ml_kem_decaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&[0u8; 1], &[]);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_dk_512 && actual == 1
        ));

        // ML-KEM-512 decaps: valid dk size, invalid ct
        let dk_512 = vec![0u8; expected_dk_512];
        let result = ml_kem_decaps::<K512, ETA1_512, ETA2_512, DU_512, DV_512>(&dk_512, &[0u8; 1]);
        assert!(matches!(
            result,
            Err(Error::InvalidCiphertextLength { expected, actual })
                if expected == expected_ct_512 && actual == 1
        ));

        // ML-KEM-1024 decaps: invalid dk
        let expected_dk_1024 = K1024 * 768 + 96;
        let expected_ct_1024 = 32 * (K1024 * DU_1024 + DV_1024);
        let result = ml_kem_decaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&[0u8; 1], &[]);
        assert!(matches!(
            result,
            Err(Error::InvalidKeyLength { expected, actual })
                if expected == expected_dk_1024 && actual == 1
        ));

        // ML-KEM-1024 decaps: valid dk size, invalid ct
        let dk_1024 = vec![0u8; expected_dk_1024];
        let result =
            ml_kem_decaps::<K1024, ETA1_1024, ETA2_1024, DU_1024, DV_1024>(&dk_1024, &[0u8; 1]);
        assert!(matches!(
            result,
            Err(Error::InvalidCiphertextLength { expected, actual })
                if expected == expected_ct_1024 && actual == 1
        ));
    }
}
