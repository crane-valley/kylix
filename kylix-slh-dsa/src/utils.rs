//! Utility functions for SLH-DSA.
//!
//! This module contains helper functions used throughout the SLH-DSA implementation,
//! including bit manipulation and encoding functions from FIPS 205.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Convert a byte array to an integer (big-endian).
///
/// FIPS 205, Algorithm 1: toInt(X, n)
#[must_use]
#[allow(dead_code)]
pub fn to_int(x: &[u8]) -> u64 {
    let mut total: u64 = 0;
    for &byte in x {
        total = (total << 8) | u64::from(byte);
    }
    total
}

/// Convert an integer to a byte array of specified length (big-endian).
///
/// FIPS 205, Algorithm 2: toByte(x, n)
#[must_use]
#[allow(dead_code)]
pub fn to_byte<const N: usize>(x: u64) -> [u8; N] {
    let mut result = [0u8; N];
    let mut val = x;
    for i in (0..N).rev() {
        result[i] = (val & 0xFF) as u8;
        val >>= 8;
    }
    result
}

/// Extract base-2^b representation from a byte array.
///
/// FIPS 205, Algorithm 3: base_2b(X, b, out_len)
///
/// Interprets X as a sequence of b-bit unsigned integers and extracts out_len of them.
///
/// # Arguments
/// * `x` - Input byte array
/// * `b` - Number of bits per output element (must be 1, 2, 4, or 8 for simplicity)
/// * `out_len` - Number of elements to extract
///
/// # Returns
/// Vector of extracted values, each in range [0, 2^b)
#[must_use]
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    debug_assert!(b > 0 && b <= 32);

    let mut result = Vec::with_capacity(out_len);
    let mask = (1u64 << b) - 1;

    // Accumulator for bits
    let mut bits: u64 = 0;
    let mut num_bits: usize = 0;
    let mut byte_idx: usize = 0;

    for _ in 0..out_len {
        // Load more bytes if needed
        while num_bits < b && byte_idx < x.len() {
            bits = (bits << 8) | u64::from(x[byte_idx]);
            num_bits += 8;
            byte_idx += 1;
        }

        // Extract b bits
        if num_bits >= b {
            num_bits -= b;
            result.push(((bits >> num_bits) & mask) as u32);
        } else {
            // Pad with zeros if not enough bits
            result.push(((bits << (b - num_bits)) & mask) as u32);
            num_bits = 0;
        }
    }

    result
}

/// Compute the checksum for WOTS+ message encoding.
///
/// csum = sum(w - 1 - msg[i]) for i in 0..len1
///
/// # Arguments
/// * `msg` - Base-w encoded message (len1 elements)
/// * `w` - Winternitz parameter (typically 16)
///
/// # Returns
/// Checksum value
#[must_use]
pub fn wots_checksum(msg: &[u32], w: u32) -> u32 {
    let mut csum: u32 = 0;
    for &m in msg {
        csum += w - 1 - m;
    }
    csum
}

/// Encode checksum as base-w representation.
///
/// # Arguments
/// * `csum` - Checksum value
/// * `lg_w` - Log2 of Winternitz parameter
/// * `len2` - Number of checksum digits
///
/// # Returns
/// Base-w encoded checksum
#[must_use]
#[allow(dead_code)]
pub fn encode_checksum(csum: u32, lg_w: usize, len2: usize) -> Vec<u32> {
    // Convert checksum to bytes, then to base-w
    let csum_bytes = to_byte::<4>(u64::from(csum << (8 - ((len2 * lg_w) % 8))));
    base_2b(&csum_bytes, lg_w, len2)
}

/// Concatenate byte slices into a single vector.
#[cfg(not(feature = "std"))]
#[must_use]
#[allow(dead_code)]
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Concatenate byte slices into a single vector.
#[cfg(feature = "std")]
#[must_use]
#[allow(dead_code)]
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    use super::*;

    #[test]
    fn test_to_int() {
        assert_eq!(to_int(&[0x01, 0x02, 0x03, 0x04]), 0x01020304);
        assert_eq!(to_int(&[0xFF]), 0xFF);
        assert_eq!(to_int(&[]), 0);
    }

    #[test]
    fn test_to_byte() {
        assert_eq!(to_byte::<4>(0x01020304), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(to_byte::<2>(0xFF), [0x00, 0xFF]);
        assert_eq!(to_byte::<1>(0x100), [0x00]); // Truncates
    }

    #[test]
    fn test_base_2b_4bit() {
        // 0xAB = 1010_1011 -> [10, 11] in base 16 (4 bits)
        let result = base_2b(&[0xAB], 4, 2);
        assert_eq!(result, vec![0xA, 0xB]);
    }

    #[test]
    fn test_base_2b_8bit() {
        let result = base_2b(&[0x12, 0x34], 8, 2);
        assert_eq!(result, vec![0x12, 0x34]);
    }

    #[test]
    fn test_wots_checksum() {
        // For w=16, each msg[i] is in [0, 15]
        // If msg = [0, 0, 0, 0], csum = 4 * 15 = 60
        assert_eq!(wots_checksum(&[0, 0, 0, 0], 16), 60);

        // If msg = [15, 15, 15, 15], csum = 0
        assert_eq!(wots_checksum(&[15, 15, 15, 15], 16), 0);

        // If msg = [8, 8, 8, 8], csum = 4 * 7 = 28
        assert_eq!(wots_checksum(&[8, 8, 8, 8], 16), 28);
    }

    #[test]
    fn test_concat() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5];
        let c = [6u8];
        assert_eq!(concat(&[&a, &b, &c]), vec![1, 2, 3, 4, 5, 6]);
    }
}
