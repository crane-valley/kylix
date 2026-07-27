//! Hash functions for ML-DSA
//!
//! Uses SHAKE128 and SHAKE256 from FIPS 202.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

/// SHAKE128 rate in bytes: the natural squeeze granularity of the sponge.
const XOF_BLOCK_BYTES: usize = 168;

/// SHAKE256 XOF wrapper for sampling and hashing.
pub struct Shake256Xof {
    reader: sha3::Shake256Reader,
}

impl Shake256Xof {
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
    block: [u8; XOF_BLOCK_BYTES],
    block_pos: usize,
    block_len: usize,
}

impl Shake128Xof {
    /// Create SHAKE128 from rho and indices.
    pub fn new(rho: &[u8; 32], i: u8, j: u8) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(rho);
        hasher.update(&[j, i]); // Note: column-major order per FIPS 204
        Self {
            reader: hasher.finalize_xof(),
            block: [0u8; XOF_BLOCK_BYTES],
            block_pos: 0,
            block_len: 0,
        }
    }

    /// Squeeze bytes from the XOF.
    // Not called from production paths; exercised by this module's unit tests.
    #[allow(dead_code)]
    #[inline]
    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut written = 0;

        if self.block_pos < self.block_len {
            let available = self.block_len - self.block_pos;
            let to_copy = available.min(out.len());
            out[..to_copy].copy_from_slice(&self.block[self.block_pos..self.block_pos + to_copy]);
            self.block_pos += to_copy;
            written = to_copy;

            if self.block_pos == self.block_len {
                self.block_pos = 0;
                self.block_len = 0;
            }
        }

        if written < out.len() {
            self.reader.read(&mut out[written..]);
        }
    }

    /// Read the next 3 bytes while buffering one SHAKE128 rate block internally.
    ///
    /// Rejection sampling consumes 3 bytes at a time; squeezing them one triple
    /// per call costs a sponge permutation per 3 bytes, so buffer a full rate
    /// block instead. The emitted byte stream is unchanged.
    #[inline]
    pub fn squeeze_three(&mut self) -> [u8; 3] {
        if self.block_len - self.block_pos < 3 {
            let carry = self.block_len - self.block_pos;
            if carry > 0 {
                self.block.copy_within(self.block_pos..self.block_len, 0);
            }
            self.reader.read(&mut self.block[carry..]);
            self.block_pos = 0;
            self.block_len = XOF_BLOCK_BYTES;
        }

        let bytes = [
            self.block[self.block_pos],
            self.block[self.block_pos + 1],
            self.block[self.block_pos + 2],
        ];
        self.block_pos += 3;

        if self.block_pos == self.block_len {
            self.block_pos = 0;
            self.block_len = 0;
        }

        bytes
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

/// Compute mu = H(tr || prefix || M, 64) without concatenating the inputs.
pub fn hash_message_parts(tr: &[u8; 64], prefix: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mu = [0u8; 64];
    h3(tr, prefix, message, &mut mu);
    mu
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

    #[test]
    fn test_shake128_squeeze_three_preserves_stream_position() {
        let rho = [0x42u8; 32];
        let mut buffered = Shake128Xof::new(&rho, 0, 0);
        let mut reference = Shake128Xof::new(&rho, 0, 0);

        // 159 triples span several 168-byte rate blocks.
        for _ in 0..159 {
            let mut out = [0u8; 3];
            reference.squeeze(&mut out);
            assert_eq!(buffered.squeeze_three(), out);
        }

        let mut buffered_tail = [0u8; 32];
        let mut reference_tail = [0u8; 32];
        buffered.squeeze(&mut buffered_tail);
        reference.squeeze(&mut reference_tail);

        assert_eq!(buffered_tail, reference_tail);
    }
}
