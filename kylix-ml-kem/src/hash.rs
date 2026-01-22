//! FIPS 203 hash functions for ML-KEM.
//!
//! This module provides the hash and XOF functions used in ML-KEM:
//! - H = SHA3-256: Hash encapsulation key
//! - G = SHA3-512: Derive seeds and keys
//! - J = SHAKE256: Implicit rejection PRF
//! - XOF = SHAKE128: Sample matrix A
//! - PRF = SHAKE256: Sample noise vectors

#![allow(dead_code)]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_256, Sha3_512, Shake128, Shake256,
};

/// H function: SHA3-256.
///
/// Used to hash the encapsulation key for domain separation.
///
/// # Arguments
/// * `input` - Data to hash
///
/// # Returns
/// 32-byte hash output
#[inline]
pub fn hash_h(input: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// G function: SHA3-512.
///
/// Used to derive seeds and keys:
/// - G(d) -> (rho, sigma) for K-PKE.KeyGen
/// - G(m || H(ek)) -> (K, r) for ML-KEM.Encaps
///
/// # Arguments
/// * `input` - Data to hash
///
/// # Returns
/// 64-byte hash output (can be split into two 32-byte values)
#[inline]
pub fn hash_g(input: &[u8]) -> [u8; 64] {
    use sha3::Digest;
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// J function: SHAKE256 for implicit rejection.
///
/// Used to derive a pseudorandom shared secret when ciphertext
/// verification fails, providing CCA security.
///
/// J(z || c) -> K_bar
///
/// # Arguments
/// * `z` - 32-byte implicit rejection secret from decapsulation key
/// * `ciphertext` - The ciphertext bytes
/// * `output` - Buffer for output (typically 32 bytes)
#[inline]
pub fn hash_j(z: &[u8; 32], ciphertext: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(z);
    hasher.update(ciphertext);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// XOF (Extendable Output Function) for sampling matrix A.
///
/// Uses SHAKE128 initialized with rho || j || i for A[i][j].
/// Note: FIPS 203 specifies column-major indexing.
pub struct Xof {
    reader: sha3::Shake128Reader,
}

impl Xof {
    /// Create a new XOF for sampling A[i][j].
    ///
    /// # Arguments
    /// * `rho` - 32-byte public seed
    /// * `i` - Row index
    /// * `j` - Column index
    ///
    /// # Note
    /// The initialization follows FIPS 203: XOF(rho || j || i)
    /// where j is the column and i is the row (column-major order).
    pub fn new(rho: &[u8; 32], i: u8, j: u8) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(rho);
        hasher.update(&[j, i]); // FIPS 203: column-major order
        let reader = hasher.finalize_xof();
        Self { reader }
    }

    /// Read bytes from the XOF.
    ///
    /// # Arguments
    /// * `out` - Buffer to fill with XOF output
    #[inline]
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// PRF function: SHAKE256 for sampling noise.
///
/// PRF(sigma, N) produces pseudorandom bytes for CBD sampling.
///
/// # Arguments
/// * `sigma` - 32-byte secret seed
/// * `nonce` - Single-byte nonce (counter)
/// * `output` - Buffer for PRF output
#[inline]
pub fn prf(sigma: &[u8; 32], nonce: u8, output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(sigma);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_h_deterministic() {
        let input = b"test input";
        let h1 = hash_h(input);
        let h2 = hash_h(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_h_different_inputs() {
        let h1 = hash_h(b"input1");
        let h2 = hash_h(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_g_deterministic() {
        let input = b"test input";
        let g1 = hash_g(input);
        let g2 = hash_g(input);
        assert_eq!(g1, g2);
    }

    #[test]
    fn test_hash_g_output_length() {
        let output = hash_g(b"test");
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_hash_j_deterministic() {
        let z = [0x42u8; 32];
        let ct = [0x01, 0x02, 0x03, 0x04];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hash_j(&z, &ct, &mut out1);
        hash_j(&z, &ct, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_hash_j_different_z() {
        let z1 = [0x00u8; 32];
        let z2 = [0x01u8; 32];
        let ct = [0x01, 0x02, 0x03, 0x04];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hash_j(&z1, &ct, &mut out1);
        hash_j(&z2, &ct, &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_xof_deterministic() {
        let rho = [0x42u8; 32];
        let mut xof1 = Xof::new(&rho, 0, 0);
        let mut xof2 = Xof::new(&rho, 0, 0);
        let mut out1 = [0u8; 100];
        let mut out2 = [0u8; 100];
        xof1.squeeze(&mut out1);
        xof2.squeeze(&mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_xof_different_indices() {
        let rho = [0x42u8; 32];
        let mut xof1 = Xof::new(&rho, 0, 0);
        let mut xof2 = Xof::new(&rho, 0, 1);
        let mut out1 = [0u8; 100];
        let mut out2 = [0u8; 100];
        xof1.squeeze(&mut out1);
        xof2.squeeze(&mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_prf_deterministic() {
        let sigma = [0x42u8; 32];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        prf(&sigma, 0, &mut out1);
        prf(&sigma, 0, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_different_nonces() {
        let sigma = [0x42u8; 32];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        prf(&sigma, 0, &mut out1);
        prf(&sigma, 1, &mut out2);
        assert_ne!(out1, out2);
    }
}
