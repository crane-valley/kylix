//! XMSS (eXtended Merkle Signature Scheme) implementation.
//!
//! XMSS provides a single-layer Merkle tree of WOTS+ keys, allowing
//! 2^h' signatures per tree where h' is the tree height.
//!
//! FIPS 205, Algorithms 9-10.

use crate::address::{Address, AdrsType};
use crate::hash::HashSuite;
use crate::wots::{wots_pk_from_sig, wots_pk_gen, wots_sign_to};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Compute a node in the XMSS Merkle tree.
///
/// FIPS 205, Algorithm 9: xmss_node(SK.seed, i, z, PK.seed, ADRS)
///
/// Computes the node at height z and index i in the XMSS tree.
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `i` - Node index at height z
/// * `z` - Height in the tree (0 = leaf level)
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
///
/// # Returns
/// Node value (n bytes)
pub fn xmss_node<H: HashSuite, const WOTS_LEN: usize>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &Address,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node: compute WOTS+ public key
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(AdrsType::WotsHash);
        leaf_adrs.set_keypair(i);
        wots_pk_gen::<H, WOTS_LEN>(sk_seed, pk_seed, &mut leaf_adrs)
    } else {
        // Internal node: hash of children
        // Pass copies of address to children to avoid mutation issues
        let left = xmss_node::<H, WOTS_LEN>(sk_seed, 2 * i, z - 1, pk_seed, adrs);
        let right = xmss_node::<H, WOTS_LEN>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

        let mut node_adrs = *adrs;
        node_adrs.set_type(AdrsType::Tree);
        node_adrs.set_tree_height(z);
        node_adrs.set_tree_index(i);
        H::h(pk_seed, &node_adrs, &left, &right)
    }
}

/// Generate an XMSS signature into a pre-allocated buffer.
///
/// FIPS 205, Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
///
/// Signs a message using the XMSS tree at the specified leaf index,
/// writing the result directly into the provided output buffer.
///
/// # Arguments
/// * `out` - Output buffer (must be exactly (WOTS_LEN + h_prime) * n bytes)
/// * `message` - Message to sign (n bytes, typically a root from lower layer)
/// * `sk_seed` - Secret seed
/// * `idx` - Leaf index to use for signing
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `h_prime` - Height of this XMSS tree
///
/// # Panics
/// Panics in debug builds if `out.len() != (WOTS_LEN + h_prime) * n`.
pub fn xmss_sign_to<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    out: &mut [u8],
    message: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &Address,
    h_prime: usize,
) {
    let n = H::N;
    let wots_sig_len = WOTS_LEN * n;
    debug_assert_eq!(out.len(), wots_sig_len + h_prime * n);

    // Generate WOTS+ signature directly into output buffer
    let mut wots_adrs = *adrs;
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_keypair(idx);
    wots_sign_to::<H, WOTS_LEN, WOTS_LEN1>(
        &mut out[..wots_sig_len],
        message,
        sk_seed,
        pk_seed,
        &mut wots_adrs,
    );

    // Compute authentication path directly into output buffer
    for j in 0..h_prime {
        let sibling_idx = (idx >> j) ^ 1;
        let node = xmss_node::<H, WOTS_LEN>(sk_seed, sibling_idx, j as u32, pk_seed, adrs);
        out[wots_sig_len + j * n..wots_sig_len + (j + 1) * n].copy_from_slice(&node);
    }
}

/// Generate an XMSS signature.
///
/// FIPS 205, Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
///
/// Signs a message using the XMSS tree at the specified leaf index.
///
/// # Arguments
/// * `message` - Message to sign (n bytes, typically a root from lower layer)
/// * `sk_seed` - Secret seed
/// * `idx` - Leaf index to use for signing
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `h_prime` - Height of this XMSS tree
///
/// # Returns
/// XMSS signature: (WOTS+ signature || authentication path)
#[allow(dead_code)]
pub fn xmss_sign<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    message: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &Address,
    h_prime: usize,
) -> Vec<u8> {
    let n = H::N;
    let mut sig = vec![0u8; WOTS_LEN * n + h_prime * n];
    xmss_sign_to::<H, WOTS_LEN, WOTS_LEN1>(&mut sig, message, sk_seed, idx, pk_seed, adrs, h_prime);
    sig
}

/// Compute XMSS public key (root) from signature.
///
/// FIPS 205, Algorithm 10 (verification part): Recovers the root from signature.
///
/// # Arguments
/// * `idx` - Leaf index used for signing
/// * `sig_xmss` - XMSS signature (WOTS+ signature || authentication path)
/// * `message` - Original message (n bytes)
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `h_prime` - Height of this XMSS tree
///
/// # Returns
/// Recovered XMSS root (n bytes)
pub fn xmss_pk_from_sig<H: HashSuite, const WOTS_LEN: usize, const WOTS_LEN1: usize>(
    idx: u32,
    sig_xmss: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    h_prime: usize,
) -> Vec<u8> {
    let n = H::N;
    let wots_sig_len = WOTS_LEN * n;

    // Extract WOTS+ signature and authentication path
    let sig_wots = &sig_xmss[..wots_sig_len];
    let auth = &sig_xmss[wots_sig_len..];

    // Recover WOTS+ public key
    let mut wots_adrs = *adrs;
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_keypair(idx);
    let mut node =
        wots_pk_from_sig::<H, WOTS_LEN, WOTS_LEN1>(sig_wots, message, pk_seed, &mut wots_adrs);

    // Climb the tree using authentication path
    let mut tree_adrs = *adrs;
    tree_adrs.set_type(AdrsType::Tree);

    for j in 0..h_prime {
        tree_adrs.set_tree_height((j + 1) as u32);

        let auth_j = &auth[j * n..(j + 1) * n];

        if (idx >> j) & 1 == 0 {
            // Current node is left child
            tree_adrs.set_tree_index(idx >> (j + 1));
            node = H::h(pk_seed, &tree_adrs, &node, auth_j);
        } else {
            // Current node is right child
            tree_adrs.set_tree_index(idx >> (j + 1));
            node = H::h(pk_seed, &tree_adrs, auth_j, &node);
        }
    }

    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;
    const H_PRIME: usize = 4; // Small tree for testing

    #[test]
    fn test_xmss_node_leaf() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let adrs = Address::tree_node(0, 0, 0, 0);

        let leaf = xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, 0, &pk_seed, &adrs);
        assert_eq!(leaf.len(), N);

        // Should be deterministic
        let adrs2 = Address::tree_node(0, 0, 0, 0);
        let leaf2 = xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, 0, &pk_seed, &adrs2);
        assert_eq!(leaf, leaf2);
    }

    #[test]
    fn test_xmss_node_different_indices() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let adrs1 = Address::tree_node(0, 0, 0, 0);
        let adrs2 = Address::tree_node(0, 0, 0, 0);

        let leaf0 = xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, 0, &pk_seed, &adrs1);
        let leaf1 = xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 1, 0, &pk_seed, &adrs2);

        assert_ne!(leaf0, leaf1);
    }

    #[test]
    fn test_xmss_node_internal() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let adrs = Address::tree_node(0, 0, 0, 0);

        // Compute root of a height-2 tree
        let root = xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, 2, &pk_seed, &adrs);
        assert_eq!(root.len(), N);
    }

    #[test]
    fn test_xmss_sign_verify_roundtrip() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let idx = 0u32;

        // Compute expected root
        let root_adrs = Address::tree_node(0, 0, 0, 0);
        let expected_root =
            xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, H_PRIME as u32, &pk_seed, &root_adrs);

        // Sign
        let sign_adrs = Address::tree_node(0, 0, 0, 0);
        let sig = xmss_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, idx, &pk_seed, &sign_adrs, H_PRIME,
        );

        // Expected signature size: WOTS_LEN * N + H_PRIME * N
        assert_eq!(sig.len(), WOTS_LEN * N + H_PRIME * N);

        // Verify
        let verify_adrs = Address::tree_node(0, 0, 0, 0);
        let recovered_root = xmss_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            idx,
            &sig,
            &message,
            &pk_seed,
            &verify_adrs,
            H_PRIME,
        );

        assert_eq!(expected_root, recovered_root);
    }

    #[test]
    fn test_xmss_different_leaf_indices() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];

        // Compute expected root
        let root_adrs = Address::tree_node(0, 0, 0, 0);
        let expected_root =
            xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, H_PRIME as u32, &pk_seed, &root_adrs);

        // Sign with different leaf indices
        for idx in 0..(1u32 << H_PRIME) {
            let sign_adrs = Address::tree_node(0, 0, 0, 0);
            let sig = xmss_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
                &message, &sk_seed, idx, &pk_seed, &sign_adrs, H_PRIME,
            );

            let verify_adrs = Address::tree_node(0, 0, 0, 0);
            let recovered_root = xmss_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
                idx,
                &sig,
                &message,
                &pk_seed,
                &verify_adrs,
                H_PRIME,
            );

            assert_eq!(expected_root, recovered_root, "Failed for leaf index {idx}");
        }
    }

    #[test]
    fn test_xmss_wrong_message_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let wrong_message = [4u8; N];
        let idx = 0u32;

        // Compute expected root
        let root_adrs = Address::tree_node(0, 0, 0, 0);
        let expected_root =
            xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, H_PRIME as u32, &pk_seed, &root_adrs);

        // Sign
        let sign_adrs = Address::tree_node(0, 0, 0, 0);
        let sig = xmss_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, idx, &pk_seed, &sign_adrs, H_PRIME,
        );

        // Verify with wrong message
        let verify_adrs = Address::tree_node(0, 0, 0, 0);
        let recovered_root = xmss_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            idx,
            &sig,
            &wrong_message,
            &pk_seed,
            &verify_adrs,
            H_PRIME,
        );

        assert_ne!(expected_root, recovered_root);
    }

    #[test]
    fn test_xmss_wrong_index_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];
        let idx = 0u32;
        let wrong_idx = 1u32;

        // Compute expected root
        let root_adrs = Address::tree_node(0, 0, 0, 0);
        let expected_root =
            xmss_node::<Shake128Hash, WOTS_LEN>(&sk_seed, 0, H_PRIME as u32, &pk_seed, &root_adrs);

        // Sign with idx=0
        let sign_adrs = Address::tree_node(0, 0, 0, 0);
        let sig = xmss_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, idx, &pk_seed, &sign_adrs, H_PRIME,
        );

        // Verify with wrong index
        let verify_adrs = Address::tree_node(0, 0, 0, 0);
        let recovered_root = xmss_pk_from_sig::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            wrong_idx,
            &sig,
            &message,
            &pk_seed,
            &verify_adrs,
            H_PRIME,
        );

        assert_ne!(expected_root, recovered_root);
    }
}
