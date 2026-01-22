//! Hash functions for ML-DSA
//!
//! Uses SHAKE128 and SHAKE256 from FIPS 202.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

/// SHAKE256 XOF wrapper for sampling and hashing.
pub struct Shake256Xof {
    reader: sha3::Shake256Reader,
}

impl Shake256Xof {
    /// Create a new SHAKE256 instance.
    pub fn new() -> Self {
        Self {
            reader: Shake256::default().finalize_xof(),
        }
    }

    /// Create SHAKE256 from initial data.
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(data);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze bytes from the XOF.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// SHAKE128 XOF wrapper for matrix expansion.
pub struct Shake128Xof {
    reader: sha3::Shake128Reader,
}

impl Shake128Xof {
    /// Create SHAKE128 from rho and indices.
    pub fn new(rho: &[u8; 32], i: u8, j: u8) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(rho);
        hasher.update(&[j, i]); // Note: column-major order per FIPS 204
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze bytes from the XOF.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// H function: SHAKE256 with specified output length.
pub fn h(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// H function with two inputs concatenated.
pub fn h2(a: &[u8], b: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(a);
    hasher.update(b);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// H function with three inputs concatenated.
pub fn h3(a: &[u8], b: &[u8], c: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// Compute tr = H(pk, 64) - hash of public key.
pub fn hash_pk(pk: &[u8]) -> [u8; 64] {
    let mut tr = [0u8; 64];
    h(pk, &mut tr);
    tr
}

/// Compute mu = H(tr || M, 64) - message representative.
pub fn hash_message(tr: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let mut mu = [0u8; 64];
    h2(tr, message, &mut mu);
    mu
}

/// Compute rho' for signing: H(K || rnd || mu, 64).
pub fn derive_rho_prime(k: &[u8; 32], rnd: &[u8; 32], mu: &[u8; 64]) -> [u8; 64] {
    let mut rho_prime = [0u8; 64];
    h3(k, rnd, mu, &mut rho_prime);
    rho_prime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_deterministic() {
        let input = b"test input";
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        h(input, &mut out1);
        h(input, &mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake128_deterministic() {
        let rho = [0u8; 32];
        let mut xof1 = Shake128Xof::new(&rho, 0, 0);
        let mut xof2 = Shake128Xof::new(&rho, 0, 0);

        let mut out1 = [0u8; 100];
        let mut out2 = [0u8; 100];

        xof1.squeeze(&mut out1);
        xof2.squeeze(&mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake128_different_indices() {
        let rho = [0u8; 32];
        let mut xof1 = Shake128Xof::new(&rho, 0, 0);
        let mut xof2 = Shake128Xof::new(&rho, 0, 1);

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        xof1.squeeze(&mut out1);
        xof2.squeeze(&mut out2);

        assert_ne!(out1, out2);
    }
}
