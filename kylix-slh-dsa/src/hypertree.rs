//! Hypertree implementation.
//!
//! The hypertree is a multi-layer structure of XMSS trees that provides
//! the main key management mechanism in SLH-DSA. It has d layers,
//! each containing XMSS trees of height h'.
//!
//! FIPS 205, Algorithms 11-12.

use crate::address::Address;
use crate::hash::HashSuite;
use crate::xmss::{xmss_node_to, xmss_pk_from_sig, xmss_sign_to};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Generate a hypertree signature into a pre-allocated buffer.
///
/// FIPS 205, Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
///
/// Signs a message through the d-layer hypertree, writing the result
/// directly into the provided output buffer.
///
/// # Arguments
/// * `out` - Output buffer (must be exactly d * (WOTS_LEN + h_prime) * n bytes)
/// * `message` - Message to sign (n bytes, typically FORS public key)
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `idx_tree` - Tree index at the bottom layer
/// * `idx_leaf` - Leaf index within the bottom tree
/// * `h_prime` - Height of each XMSS tree
/// * `d` - Number of hypertree layers
///
/// # Panics
/// Panics if `out` is not exactly `d * (WOTS_LEN + h_prime) * n` bytes.
pub fn ht_sign_to<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    out: &mut [u8],
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    h_prime: usize,
    d: usize,
) {
    let n = H::N;
    let xmss_sig_len = WOTS_LEN * n + h_prime * n;
    debug_assert_eq!(out.len(), d * xmss_sig_len);

    // Sign at layer 0 (bottom layer)
    let mut adrs = Address::new();
    adrs.set_layer(0);
    adrs.set_tree(idx_tree);

    xmss_sign_to::<H, WOTS_LEN, WOTS_LEN1>(
        &mut out[..xmss_sig_len],
        message,
        sk_seed,
        idx_leaf,
        pk_seed,
        &adrs,
        h_prime,
    );

    // Get root for next layer (read back from buffer)
    let mut root = xmss_pk_from_sig::<H, WOTS_LEN, WOTS_LEN1>(
        idx_leaf,
        &out[..xmss_sig_len],
        message,
        pk_seed,
        &adrs,
        h_prime,
    );

    // Sign at each subsequent layer
    let mut current_idx_tree = idx_tree;
    for j in 1..d {
        let idx_leaf_j = (current_idx_tree & ((1 << h_prime) - 1)) as u32;
        current_idx_tree >>= h_prime;

        adrs.set_layer(j as u32);
        adrs.set_tree(current_idx_tree);

        let offset = j * xmss_sig_len;
        xmss_sign_to::<H, WOTS_LEN, WOTS_LEN1>(
            &mut out[offset..offset + xmss_sig_len],
            &root,
            sk_seed,
            idx_leaf_j,
            pk_seed,
            &adrs,
            h_prime,
        );

        // Get root for next layer (if not the last layer)
        if j < d - 1 {
            root = xmss_pk_from_sig::<H, WOTS_LEN, WOTS_LEN1>(
                idx_leaf_j,
                &out[offset..offset + xmss_sig_len],
                &root,
                pk_seed,
                &adrs,
                h_prime,
            );
        }
    }
}

/// Verify a hypertree signature.
///
/// FIPS 205, Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
///
/// Verifies a signature through the d-layer hypertree.
///
/// # Arguments
/// * `message` - Original message (n bytes)
/// * `sig_ht` - Hypertree signature
/// * `pk_seed` - Public seed
/// * `idx_tree` - Tree index at the bottom layer
/// * `idx_leaf` - Leaf index within the bottom tree
/// * `pk_root` - Expected hypertree root
/// * `h_prime` - Height of each XMSS tree
/// * `d` - Number of hypertree layers
///
/// # Returns
/// true if signature is valid
pub fn ht_verify<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    message: &[u8],
    sig_ht: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
    h_prime: usize,
    d: usize,
) -> bool {
    let n = H::N;
    let xmss_sig_len = WOTS_LEN * n + h_prime * n;

    // Verify at layer 0 (bottom layer)
    let mut adrs = Address::new();
    adrs.set_layer(0);
    adrs.set_tree(idx_tree);

    let sig_xmss_0 = &sig_ht[..xmss_sig_len];
    let mut node = xmss_pk_from_sig::<H, WOTS_LEN, WOTS_LEN1>(
        idx_leaf, sig_xmss_0, message, pk_seed, &adrs, h_prime,
    );

    // Verify at each subsequent layer
    let mut current_idx_tree = idx_tree;
    for j in 1..d {
        // Extract leaf index and tree index for this layer
        let idx_leaf_j = (current_idx_tree & ((1 << h_prime) - 1)) as u32;
        current_idx_tree >>= h_prime;

        adrs.set_layer(j as u32);
        adrs.set_tree(current_idx_tree);

        let sig_xmss_j = &sig_ht[j * xmss_sig_len..(j + 1) * xmss_sig_len];
        node = xmss_pk_from_sig::<H, WOTS_LEN, WOTS_LEN1>(
            idx_leaf_j, sig_xmss_j, &node, pk_seed, &adrs, h_prime,
        );
    }

    // Compare with expected root
    node == pk_root
}

/// Compute the hypertree root (public key component).
///
/// This is used during key generation to compute PK.root.
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `h_prime` - Height of each XMSS tree
/// * `d` - Number of hypertree layers
///
/// # Returns
/// Hypertree root (n bytes)
pub fn ht_root<H: HashSuite, const WOTS_LEN: usize>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    h_prime: usize,
    d: usize,
) -> Vec<u8> {
    let n = H::N;
    // The root is the root of the top-layer XMSS tree (layer d-1, tree 0)
    let mut adrs = Address::new();
    adrs.set_layer((d - 1) as u32);
    adrs.set_tree(0);

    let mut root = vec![0u8; n];
    xmss_node_to::<H, WOTS_LEN>(&mut root, sk_seed, 0, h_prime as u32, pk_seed, &adrs);
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;
    const H_PRIME: usize = 3; // Small for testing
    const D: usize = 2; // Small for testing

    /// Vec-returning wrapper around `ht_sign_to` for test convenience.
    fn ht_sign<H: HashSuite, const WL: usize, const WL1: usize>(
        message: &[u8],
        sk_seed: &[u8],
        pk_seed: &[u8],
        idx_tree: u64,
        idx_leaf: u32,
        h_prime: usize,
        d: usize,
    ) -> Vec<u8> {
        let n = H::N;
        let xmss_sig_len = WL * n + h_prime * n;
        let mut sig_ht = vec![0u8; d * xmss_sig_len];
        ht_sign_to::<H, WL, WL1>(
            &mut sig_ht,
            message,
            sk_seed,
            pk_seed,
            idx_tree,
            idx_leaf,
            h_prime,
            d,
        );
        sig_ht
    }

    #[test]
    fn test_ht_sign_size() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];

        let sig = ht_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, 0, 0, H_PRIME, D,
        );

        // Expected size: D * (WOTS_LEN * N + H_PRIME * N)
        let expected_size = D * (WOTS_LEN * N + H_PRIME * N);
        assert_eq!(sig.len(), expected_size);
    }

    #[test]
    fn test_ht_sign_verify_roundtrip() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let idx_tree = 0u64;
        let idx_leaf = 0u32;

        // Compute expected root
        let pk_root = ht_root::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);

        // Sign
        let sig = ht_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, idx_tree, idx_leaf, H_PRIME, D,
        );

        // Verify
        let valid = ht_verify::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sig, &pk_seed, idx_tree, idx_leaf, &pk_root, H_PRIME, D,
        );

        assert!(valid);
    }

    #[test]
    fn test_ht_different_leaf_indices() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];

        // Compute expected root
        let pk_root = ht_root::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);

        // Test with different leaf indices at the bottom layer
        let max_leaves = 1u32 << H_PRIME;
        for idx_leaf in 0..max_leaves {
            let sig = ht_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
                &message, &sk_seed, &pk_seed, 0, idx_leaf, H_PRIME, D,
            );

            let valid = ht_verify::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
                &message, &sig, &pk_seed, 0, idx_leaf, &pk_root, H_PRIME, D,
            );

            assert!(valid, "Failed for idx_leaf = {idx_leaf}");
        }
    }

    #[test]
    fn test_ht_wrong_message_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let wrong_message = [4u8; N];

        // Compute expected root
        let pk_root = ht_root::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);

        // Sign
        let sig = ht_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, 0, 0, H_PRIME, D,
        );

        // Verify with wrong message
        let valid = ht_verify::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &wrong_message,
            &sig,
            &pk_seed,
            0,
            0,
            &pk_root,
            H_PRIME,
            D,
        );

        assert!(!valid);
    }

    #[test]
    fn test_ht_wrong_root_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let wrong_root = [0u8; N];

        // Sign
        let sig = ht_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, 0, 0, H_PRIME, D,
        );

        // Verify with wrong root
        let valid = ht_verify::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message,
            &sig,
            &pk_seed,
            0,
            0,
            &wrong_root,
            H_PRIME,
            D,
        );

        assert!(!valid);
    }

    #[test]
    fn test_ht_root_determinism() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];

        let root1 = ht_root::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);
        let root2 = ht_root::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);

        assert_eq!(root1, root2);
        assert_eq!(root1.len(), N);
    }
}
