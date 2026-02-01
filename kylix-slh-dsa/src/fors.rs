//! FORS (Forest of Random Subsets) implementation.
//!
//! FORS is a few-time signature scheme that signs the message hash in SLH-DSA.
//! It uses k trees of height a, providing k*a bits of security against
//! message-dependent attacks.
//!
//! FIPS 205, Algorithms 15-17.

// When parallel feature is enabled, the sign module uses parallel versions
// from the parallel module. These functions are still used in tests.
#![cfg_attr(feature = "parallel", allow(dead_code))]

use crate::address::{Address, AdrsType};
use crate::hash::HashSuite;
use crate::utils::base_2b;
use zeroize::Zeroizing;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Generate a FORS secret key element.
///
/// FIPS 205, Algorithm 15: fors_SKgen(SK.seed, PK.seed, ADRS, idx)
///
/// Generates a single secret key element for FORS.
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address (type ForsPrf)
///
/// # Returns
/// Secret key element (n bytes) wrapped in `Zeroizing` for automatic memory cleanup
pub fn fors_sk_gen<H: HashSuite>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
) -> Zeroizing<Vec<u8>> {
    H::prf(pk_seed, sk_seed, adrs)
}

/// Compute a node in a single FORS tree.
///
/// FIPS 205, Algorithm 16: fors_node(SK.seed, i, z, PK.seed, ADRS)
///
/// Computes the node at height z and index i within the tree specified by ADRS.
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `tree_idx` - Which FORS tree (0 to k-1)
/// * `i` - Node index at height z within this tree
/// * `z` - Height in the tree (0 = leaf level)
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `t` - Number of leaves per tree (2^a)
///
/// # Returns
/// Node value (n bytes)
pub(crate) fn fors_tree_node<H: HashSuite>(
    sk_seed: &[u8],
    tree_idx: u32,
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &mut Address,
    t: u32,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node: hash of secret key element
        // Global leaf index = tree_idx * t + i
        let global_idx = tree_idx * t + i;

        let mut sk_adrs = adrs.with_type(AdrsType::ForsPrf);
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index(global_idx);
        let sk = fors_sk_gen::<H>(sk_seed, pk_seed, &sk_adrs);

        adrs.set_type(AdrsType::ForsTree);
        adrs.set_tree_height(0);
        adrs.set_tree_index(global_idx);
        H::f(pk_seed, adrs, &sk)
    } else {
        // Internal node: hash of children
        let left = fors_tree_node::<H>(sk_seed, tree_idx, 2 * i, z - 1, pk_seed, adrs, t);
        let right = fors_tree_node::<H>(sk_seed, tree_idx, 2 * i + 1, z - 1, pk_seed, adrs, t);

        // Global index for this internal node
        let nodes_at_level = t >> z;
        let global_idx = tree_idx * nodes_at_level + i;

        adrs.set_type(AdrsType::ForsTree);
        adrs.set_tree_height(z);
        adrs.set_tree_index(global_idx);
        H::h(pk_seed, adrs, &left, &right)
    }
}

/// Generate a FORS signature into a pre-allocated buffer.
///
/// FIPS 205, Algorithm 17: fors_sign(md, SK.seed, PK.seed, ADRS)
///
/// Signs a message digest using FORS, writing the result directly
/// into the provided output buffer.
///
/// # Arguments
/// * `out` - Output buffer (must be exactly k * (1 + a) * n bytes)
/// * `md` - Message digest (determines which leaves to reveal)
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `k` - Number of FORS trees
/// * `a` - Height of each FORS tree
///
/// # Panics
/// Panics in debug builds if `out.len() != k * (1 + a) * n`.
pub fn fors_sign_to<H: HashSuite>(
    out: &mut [u8],
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    k: usize,
    a: usize,
) {
    let n = H::N;
    let t = 1u32 << a;
    let chunk_size = n + a * n; // Per-tree signature size
    debug_assert_eq!(out.len(), k * chunk_size);

    // Extract k indices from message digest, each a bits
    let indices = base_2b(md, a, k);

    for i in 0..k {
        let idx = indices[i];
        let tree_idx = i as u32;
        let global_leaf_idx = tree_idx * t + idx;
        let tree_out = &mut out[i * chunk_size..(i + 1) * chunk_size];

        // Generate secret key element
        let mut sk_adrs = adrs.with_type(AdrsType::ForsPrf);
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index(global_leaf_idx);
        let sk = fors_sk_gen::<H>(sk_seed, pk_seed, &sk_adrs);
        tree_out[..n].copy_from_slice(&sk);

        // Compute authentication path
        for j in 0..a {
            let sibling_in_tree = (idx >> j) ^ 1;
            let auth_node = fors_tree_node::<H>(
                sk_seed,
                tree_idx,
                sibling_in_tree,
                j as u32,
                pk_seed,
                adrs,
                t,
            );
            tree_out[n + j * n..n + (j + 1) * n].copy_from_slice(&auth_node);
        }
    }
}

/// Generate a FORS signature.
///
/// FIPS 205, Algorithm 17: fors_sign(md, SK.seed, PK.seed, ADRS)
///
/// Signs a message digest using FORS.
///
/// # Arguments
/// * `md` - Message digest (determines which leaves to reveal)
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `k` - Number of FORS trees
/// * `a` - Height of each FORS tree
///
/// # Returns
/// FORS signature: k * (secret key element || authentication path)
#[allow(dead_code)]
pub fn fors_sign<H: HashSuite>(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = H::N;
    let mut sig = vec![0u8; k * (n + a * n)];
    fors_sign_to::<H>(&mut sig, md, sk_seed, pk_seed, adrs, k, a);
    sig
}

/// Compute FORS public key from signature.
///
/// Recovers the FORS public key from a signature and message digest.
///
/// # Arguments
/// * `sig_fors` - FORS signature
/// * `md` - Message digest
/// * `pk_seed` - Public seed
/// * `adrs` - Address (will be modified during computation)
/// * `k` - Number of FORS trees
/// * `a` - Height of each FORS tree
///
/// # Returns
/// Recovered FORS public key (n bytes)
pub fn fors_pk_from_sig<H: HashSuite>(
    sig_fors: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = H::N;
    let t = 1u32 << a;

    // Extract indices from message digest
    let indices = base_2b(md, a, k);

    // Collect all tree roots
    let mut roots = Vec::with_capacity(k * n);

    let sig_elem_size = n + a * n; // sk element + auth path

    for i in 0..k {
        let sig_i = &sig_fors[i * sig_elem_size..(i + 1) * sig_elem_size];
        let sk = &sig_i[..n];
        let auth = &sig_i[n..];

        let idx = indices[i]; // Leaf index within this tree
        let tree_idx = i as u32;
        let global_leaf_idx = tree_idx * t + idx;

        // Compute leaf from secret key
        adrs.set_type(AdrsType::ForsTree);
        adrs.set_tree_height(0);
        adrs.set_tree_index(global_leaf_idx);
        let mut node = H::f(pk_seed, adrs, sk);

        // Climb the tree using authentication path
        for j in 0..a {
            let auth_j = &auth[j * n..(j + 1) * n];

            // Compute parent node
            let parent_in_tree = idx >> (j + 1);
            let nodes_at_parent_level = t >> (j + 1);
            let global_parent_idx = tree_idx * nodes_at_parent_level + parent_in_tree;

            adrs.set_tree_height((j + 1) as u32);
            adrs.set_tree_index(global_parent_idx);

            if (idx >> j) & 1 == 0 {
                // Current node is left child
                node = H::h(pk_seed, adrs, &node, auth_j);
            } else {
                // Current node is right child
                node = H::h(pk_seed, adrs, auth_j, &node);
            }
        }

        roots.extend_from_slice(&node);
    }

    // Compress all roots to get public key
    let fors_pk_adrs = adrs.with_type(AdrsType::ForsPk);
    H::t_l(pk_seed, &fors_pk_adrs, &roots)
}

/// Compute FORS public key directly (for testing/keygen).
///
/// # Arguments
/// * `sk_seed` - Secret seed
/// * `pk_seed` - Public seed
/// * `adrs` - Address
/// * `k` - Number of FORS trees
/// * `a` - Height of each FORS tree
///
/// # Returns
/// FORS public key (n bytes)
#[allow(dead_code)]
pub fn fors_pk_gen<H: HashSuite>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = H::N;
    let t = 1u32 << a;

    let mut roots = Vec::with_capacity(k * n);

    for i in 0..k {
        let root = fors_tree_node::<H>(sk_seed, i as u32, 0, a as u32, pk_seed, adrs, t);
        roots.extend_from_slice(&root);
    }

    let fors_pk_adrs = adrs.with_type(AdrsType::ForsPk);
    H::t_l(pk_seed, &fors_pk_adrs, &roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;

    const N: usize = 16;
    const K: usize = 4; // Small for testing
    const A: usize = 3; // Small tree height

    #[test]
    fn test_fors_sk_gen_determinism() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let adrs = Address::fors_prf(0, 0, 0, 0, 0);

        let sk1 = fors_sk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &adrs);
        let sk2 = fors_sk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &adrs);

        assert_eq!(sk1.len(), N);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_fors_sk_gen_different_indices() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let adrs1 = Address::fors_prf(0, 0, 0, 0, 0);
        let adrs2 = Address::fors_prf(0, 0, 0, 0, 1);

        let sk1 = fors_sk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &adrs1);
        let sk2 = fors_sk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &adrs2);

        assert_ne!(sk1, sk2);
    }

    #[test]
    fn test_fors_tree_node_leaf() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let mut adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let t = 1u32 << A;

        let leaf = fors_tree_node::<Shake128Hash>(&sk_seed, 0, 0, 0, &pk_seed, &mut adrs, t);
        assert_eq!(leaf.len(), N);
    }

    #[test]
    fn test_fors_tree_node_root() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let mut adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let t = 1u32 << A;

        let root = fors_tree_node::<Shake128Hash>(&sk_seed, 0, 0, A as u32, &pk_seed, &mut adrs, t);
        assert_eq!(root.len(), N);
    }

    #[test]
    fn test_fors_sign_size() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let md = [0u8; 8]; // Enough for K * A bits
        let mut adrs = Address::fors_tree(0, 0, 0, 0, 0);

        let sig = fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut adrs, K, A);

        // Expected size: K * (N + A * N) = K * N * (1 + A)
        assert_eq!(sig.len(), K * N * (1 + A));
    }

    #[test]
    fn test_fors_roundtrip() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let md = [0x55u8; 8]; // Some arbitrary digest

        // Compute expected public key
        let mut pk_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let expected_pk = fors_pk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &mut pk_adrs, K, A);

        // Sign
        let mut sign_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let sig = fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut sign_adrs, K, A);

        // Verify
        let mut verify_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let recovered_pk =
            fors_pk_from_sig::<Shake128Hash>(&sig, &md, &pk_seed, &mut verify_adrs, K, A);

        assert_eq!(expected_pk, recovered_pk);
    }

    #[test]
    fn test_fors_different_messages() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];

        // Compute expected pk
        let mut pk_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let expected_pk = fors_pk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &mut pk_adrs, K, A);

        // Test with multiple different message digests
        for byte in 0..=255u8 {
            let md = [byte; 8];
            let mut sign_adrs = Address::fors_tree(0, 0, 0, 0, 0);
            let sig = fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut sign_adrs, K, A);

            let mut verify_adrs = Address::fors_tree(0, 0, 0, 0, 0);
            let recovered_pk =
                fors_pk_from_sig::<Shake128Hash>(&sig, &md, &pk_seed, &mut verify_adrs, K, A);

            assert_eq!(expected_pk, recovered_pk, "Failed for md byte {byte}");
        }
    }

    #[test]
    fn test_fors_wrong_md_fails() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let md = [0x55u8; 8];
        let wrong_md = [0xAAu8; 8];

        // Compute expected pk
        let mut pk_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let expected_pk = fors_pk_gen::<Shake128Hash>(&sk_seed, &pk_seed, &mut pk_adrs, K, A);

        // Sign with correct md
        let mut sign_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let sig = fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut sign_adrs, K, A);

        // Verify with wrong md
        let mut verify_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let recovered_pk =
            fors_pk_from_sig::<Shake128Hash>(&sig, &wrong_md, &pk_seed, &mut verify_adrs, K, A);

        assert_ne!(expected_pk, recovered_pk);
    }
}
