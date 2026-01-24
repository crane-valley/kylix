//! WOTS+ (Winternitz One-Time Signature) implementation.
//!
//! WOTS+ is a one-time signature scheme used as a building block in SLH-DSA.
//! It provides efficient signatures with a trade-off between signature size
//! and signing/verification time controlled by the Winternitz parameter w.
//!
//! FIPS 205, Algorithms 5-8.

use crate::address::{Address, AdrsType};
use crate::hash::HashSuite;
use crate::params::common::{LG_W, W};
use crate::utils::{base_2b, wots_checksum};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Compute a single step of the WOTS+ chain.
///
/// FIPS 205, Algorithm 5: chain(X, i, s, PK.seed, ADRS)
///
/// Applies the chaining function F repeatedly s times, starting from input X
/// at chain position i.
///
/// # Arguments
/// * `x` - Starting value (n bytes)
/// * `i` - Starting index in the chain
/// * `s` - Number of steps to take
/// * `pk_seed` - Public seed
/// * `adrs` - Address (must have type WotsHash)
///
/// # Returns
/// Result after s chain applications
pub fn wots_chain<H: HashSuite>(
    x: &[u8],
    i: u32,
    s: u32,
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    if s == 0 {
        return x.to_vec();
    }

    let mut result = x.to_vec();

    for j in i..(i + s) {
        adrs.set_hash(j);
        result = H::f(pk_seed, adrs, &result);
    }

    result
}

/// Generate a WOTS+ public key.
///
/// FIPS 205, Algorithm 6: wots_PKgen(SK.seed, PK.seed, ADRS)
///
/// Generates a WOTS+ public key by computing the full chain for each
/// secret key element and compressing the result.
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
///
/// # Returns
/// WOTS+ public key (n bytes)
pub fn wots_pk_gen<H: HashSuite, const WOTS_LEN: usize>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let w = W as u32;

    // Compute sk_adrs for secret key generation
    let mut sk_adrs = adrs.with_type(AdrsType::WotsPrf);

    // Compute wots_pk_adrs for public key compression
    let wots_pk_adrs = adrs.with_type(AdrsType::WotsPk);

    // tmp will hold all chain endpoints
    let mut tmp = Vec::with_capacity(WOTS_LEN * H::N);

    for i in 0..WOTS_LEN {
        // Generate secret key element
        sk_adrs.set_chain(i as u32);
        let sk_i = H::prf(pk_seed, sk_seed, &sk_adrs);

        // Compute chain endpoint
        adrs.set_chain(i as u32);
        let chain_end = wots_chain::<H>(&sk_i, 0, w - 1, pk_seed, adrs);
        tmp.extend_from_slice(&chain_end);
    }

    // Compress to get public key
    H::t_l(pk_seed, &wots_pk_adrs, &tmp)
}

/// Generate a WOTS+ signature.
///
/// FIPS 205, Algorithm 7: wots_sign(M, SK.seed, PK.seed, ADRS)
///
/// Signs an n-byte message using WOTS+.
///
/// # Arguments
/// * `message` - Message to sign (n bytes)
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
///
/// # Returns
/// WOTS+ signature (WOTS_LEN * n bytes)
pub fn wots_sign<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let w = W as u32;

    // Convert message to base-w representation
    let mut msg = base_2b(message, LG_W, WOTS_LEN1);

    // Compute checksum
    let csum = wots_checksum(&msg, w);

    // Encode checksum and append
    let len2 = WOTS_LEN - WOTS_LEN1;
    let csum_bytes = ((csum as u64) << (8 - ((len2 * LG_W) % 8))) as u32;
    let csum_total_bits = len2 * LG_W;
    let csum_bytes_needed = (csum_total_bits + 7) / 8;

    let mut csum_buf = [0u8; 4];
    csum_buf[4 - csum_bytes_needed..].copy_from_slice(&csum_bytes.to_be_bytes()[4 - csum_bytes_needed..]);
    let csum_digits = base_2b(&csum_buf[4 - csum_bytes_needed..], LG_W, len2);
    msg.extend(csum_digits);

    // Compute sk_adrs for secret key generation
    let mut sk_adrs = adrs.with_type(AdrsType::WotsPrf);

    // Generate signature
    let mut sig = Vec::with_capacity(WOTS_LEN * H::N);

    for i in 0..WOTS_LEN {
        sk_adrs.set_chain(i as u32);
        let sk_i = H::prf(pk_seed, sk_seed, &sk_adrs);

        adrs.set_chain(i as u32);
        let sig_i = wots_chain::<H>(&sk_i, 0, msg[i], pk_seed, adrs);
        sig.extend_from_slice(&sig_i);
    }

    sig
}

/// Compute WOTS+ public key from signature.
///
/// FIPS 205, Algorithm 8: wots_PKFromSig(sig, M, PK.seed, ADRS)
///
/// Recovers the WOTS+ public key from a signature and message.
/// Used during verification.
///
/// # Arguments
/// * `sig` - WOTS+ signature (WOTS_LEN * n bytes)
/// * `message` - Original message (n bytes)
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
///
/// # Returns
/// Recovered WOTS+ public key (n bytes)
pub fn wots_pk_from_sig<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let w = W as u32;
    let n = H::N;

    // Convert message to base-w representation
    let mut msg = base_2b(message, LG_W, WOTS_LEN1);

    // Compute checksum
    let csum = wots_checksum(&msg, w);

    // Encode checksum and append
    let len2 = WOTS_LEN - WOTS_LEN1;
    let csum_bytes = ((csum as u64) << (8 - ((len2 * LG_W) % 8))) as u32;
    let csum_total_bits = len2 * LG_W;
    let csum_bytes_needed = (csum_total_bits + 7) / 8;

    let mut csum_buf = [0u8; 4];
    csum_buf[4 - csum_bytes_needed..].copy_from_slice(&csum_bytes.to_be_bytes()[4 - csum_bytes_needed..]);
    let csum_digits = base_2b(&csum_buf[4 - csum_bytes_needed..], LG_W, len2);
    msg.extend(csum_digits);

    // Compute wots_pk_adrs for public key compression
    let wots_pk_adrs = adrs.with_type(AdrsType::WotsPk);

    // Compute chain endpoints from signature
    let mut tmp = Vec::with_capacity(WOTS_LEN * n);

    for i in 0..WOTS_LEN {
        adrs.set_chain(i as u32);
        let sig_i = &sig[i * n..(i + 1) * n];
        let chain_end = wots_chain::<H>(sig_i, msg[i], w - 1 - msg[i], pk_seed, adrs);
        tmp.extend_from_slice(&chain_end);
    }

    // Compress to get public key
    H::t_l(pk_seed, &wots_pk_adrs, &tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;

    #[test]
    fn test_wots_chain_zero_steps() {
        let x = [0u8; N];
        let pk_seed = [1u8; N];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let result = wots_chain::<Shake128Hash>(&x, 0, 0, &pk_seed, &mut adrs);
        assert_eq!(result, x.to_vec());
    }

    #[test]
    fn test_wots_chain_determinism() {
        let x = [0u8; N];
        let pk_seed = [1u8; N];
        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);

        let result1 = wots_chain::<Shake128Hash>(&x, 0, 5, &pk_seed, &mut adrs1);
        let result2 = wots_chain::<Shake128Hash>(&x, 0, 5, &pk_seed, &mut adrs2);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), N);
    }

    #[test]
    fn test_wots_chain_composition() {
        // chain(x, 0, 5) should equal chain(chain(x, 0, 3), 3, 2)
        let x = [0u8; N];
        let pk_seed = [1u8; N];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let full = wots_chain::<Shake128Hash>(&x, 0, 5, &pk_seed, &mut adrs);

        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);
        let partial1 = wots_chain::<Shake128Hash>(&x, 0, 3, &pk_seed, &mut adrs1);
        let partial2 = wots_chain::<Shake128Hash>(&partial1, 3, 2, &pk_seed, &mut adrs2);

        assert_eq!(full, partial2);
    }

    #[test]
    fn test_wots_pk_gen() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let pk = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs);
        assert_eq!(pk.len(), N);

        // Determinism check
        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);
        let pk2 = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_wots_sign_verify_roundtrip() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        // Generate public key
        let mut pk_adrs = Address::wots_hash(0, 0, 0, 0, 0);
        let pk = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut pk_adrs);

        // Sign
        let sig = wots_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message,
            &sk_seed,
            &pk_seed,
            &mut adrs,
        );
        assert_eq!(sig.len(), WOTS_LEN * N);

        // Recover public key from signature
        let mut verify_adrs = Address::wots_hash(0, 0, 0, 0, 0);
        let recovered_pk = wots_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &sig,
            &message,
            &pk_seed,
            &mut verify_adrs,
        );

        assert_eq!(pk, recovered_pk);
    }

    #[test]
    fn test_wots_wrong_message_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let wrong_message = [4u8; N];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        // Generate public key
        let mut pk_adrs = Address::wots_hash(0, 0, 0, 0, 0);
        let pk = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut pk_adrs);

        // Sign correct message
        let sig = wots_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message,
            &sk_seed,
            &pk_seed,
            &mut adrs,
        );

        // Try to verify with wrong message
        let mut verify_adrs = Address::wots_hash(0, 0, 0, 0, 0);
        let recovered_pk = wots_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &sig,
            &wrong_message,
            &pk_seed,
            &mut verify_adrs,
        );

        assert_ne!(pk, recovered_pk);
    }

    #[test]
    fn test_wots_different_addresses() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];

        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 1, 0, 0); // Different keypair

        let pk1 = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs1);
        let pk2 = wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs2);

        // Different addresses should produce different keys
        assert_ne!(pk1, pk2);
    }
}
