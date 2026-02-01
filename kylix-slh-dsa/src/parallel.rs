//! Parallel implementations of SLH-DSA building blocks.
//!
//! This module provides parallelized versions of the computationally intensive
//! operations in SLH-DSA using Rayon for multi-threading.
//!
//! The main parallelization opportunities are:
//! - **FORS**: K independent trees can be computed in parallel
//! - **WOTS+**: WOTS_LEN independent chain computations
//! - **XMSS**: Left/right subtree computations can be parallelized

// Allow unused functions - these are available for future hypertree parallelization
// and are tested via unit tests
#![allow(dead_code)]

use crate::address::{Address, AdrsType};
use crate::fors::fors_tree_node_to;
use crate::hash::HashSuite;
use crate::params::common::{LG_W, W};
use crate::utils::base_2b;
use crate::wots::{encode_checksum, wots_chain_to};
use crate::xmss::xmss_node_to;

use rayon::prelude::*;
use std::vec::Vec;
use zeroize::Zeroize;

// ============================================================================
// WOTS+ Parallel Implementation
// ============================================================================

/// Generate a WOTS+ public key in parallel.
///
/// Parallelizes the chain computations across WOTS_LEN chains.
pub fn wots_pk_gen_parallel<H: HashSuite + Send + Sync, const WOTS_LEN: usize>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let n = H::N;
    let w = W as u32;

    // Compute base addresses
    let sk_adrs_base = adrs.with_type(AdrsType::WotsPrf);
    let wots_pk_adrs = adrs.with_type(AdrsType::WotsPk);
    let hash_adrs_base = *adrs;

    // Pre-allocate buffer and compute chains directly into it
    let mut tmp = vec![0u8; WOTS_LEN * n];
    tmp.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        let mut sk_adrs = sk_adrs_base;
        sk_adrs.set_chain(i as u32);
        let mut sk_buf = [0u8; 32];
        H::prf_to(&mut sk_buf[..n], pk_seed, sk_seed, &sk_adrs);

        let mut hash_adrs = hash_adrs_base;
        hash_adrs.set_chain(i as u32);
        wots_chain_to::<H>(chunk, &sk_buf[..n], 0, w - 1, pk_seed, &mut hash_adrs);
        sk_buf.zeroize();
    });

    H::t_l(pk_seed, &wots_pk_adrs, &tmp)
}

/// Generate a WOTS+ signature in parallel into a pre-allocated buffer.
///
/// Parallelizes the chain computations across WOTS_LEN chains.
pub fn wots_sign_parallel_to<
    H: HashSuite + Send + Sync,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
>(
    out: &mut [u8],
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) {
    let n = H::N;
    debug_assert_eq!(out.len(), WOTS_LEN * n);

    // Convert message to base-w representation and append checksum
    let mut msg = base_2b(message, LG_W, WOTS_LEN1);
    msg.extend(encode_checksum(&msg, WOTS_LEN, WOTS_LEN1));

    // Compute base addresses
    let sk_adrs_base = adrs.with_type(AdrsType::WotsPrf);
    let hash_adrs_base = *adrs;

    // Parallel signature generation directly into output buffer
    out.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        let mut sk_adrs = sk_adrs_base;
        sk_adrs.set_chain(i as u32);
        let mut sk_buf = [0u8; 32];
        H::prf_to(&mut sk_buf[..n], pk_seed, sk_seed, &sk_adrs);

        let mut hash_adrs = hash_adrs_base;
        hash_adrs.set_chain(i as u32);
        wots_chain_to::<H>(chunk, &sk_buf[..n], 0, msg[i], pk_seed, &mut hash_adrs);
        sk_buf.zeroize();
    });
}

/// Generate a WOTS+ signature in parallel.
///
/// Parallelizes the chain computations across WOTS_LEN chains.
pub fn wots_sign_parallel<
    H: HashSuite + Send + Sync,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
>(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let mut sig = vec![0u8; WOTS_LEN * H::N];
    wots_sign_parallel_to::<H, WOTS_LEN, WOTS_LEN1>(&mut sig, message, sk_seed, pk_seed, adrs);
    sig
}

/// Compute WOTS+ public key from signature in parallel.
pub fn wots_pk_from_sig_parallel<
    H: HashSuite + Send + Sync,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
>(
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Address,
) -> Vec<u8> {
    let w = W as u32;
    let n = H::N;

    // Convert message to base-w representation and append checksum
    let mut msg = base_2b(message, LG_W, WOTS_LEN1);
    msg.extend(encode_checksum(&msg, WOTS_LEN, WOTS_LEN1));

    // Compute base addresses
    let wots_pk_adrs = adrs.with_type(AdrsType::WotsPk);
    let hash_adrs_base = *adrs;

    // Pre-allocate buffer and compute chains directly into it
    let mut tmp = vec![0u8; WOTS_LEN * n];
    tmp.par_chunks_mut(n).enumerate().for_each(|(i, chunk)| {
        let mut hash_adrs = hash_adrs_base;
        hash_adrs.set_chain(i as u32);
        let sig_i = &sig[i * n..(i + 1) * n];
        wots_chain_to::<H>(
            chunk,
            sig_i,
            msg[i],
            w - 1 - msg[i],
            pk_seed,
            &mut hash_adrs,
        );
    });

    H::t_l(pk_seed, &wots_pk_adrs, &tmp)
}

// ============================================================================
// FORS Parallel Implementation
// ============================================================================

/// Generate a FORS signature in parallel into a pre-allocated buffer.
///
/// Parallelizes across K independent FORS trees using `par_chunks_mut`.
pub fn fors_sign_parallel_to<H: HashSuite + Send + Sync>(
    out: &mut [u8],
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    k: usize,
    a: usize,
) {
    let n = H::N;
    let t = 1u32 << a;
    let chunk_size = n + a * n;
    debug_assert_eq!(out.len(), k * chunk_size);

    // Extract k indices from message digest
    let indices = base_2b(md, a, k);

    // Process K trees in parallel, each writing directly into its chunk
    out.par_chunks_mut(chunk_size)
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = indices[i];
            let tree_idx = i as u32;
            let global_leaf_idx = tree_idx * t + idx;

            // Generate secret key element using prf_to
            let mut sk_adrs = adrs.with_type(AdrsType::ForsPrf);
            sk_adrs.set_tree_height(0);
            sk_adrs.set_tree_index(global_leaf_idx);
            H::prf_to(&mut chunk[..n], pk_seed, sk_seed, &sk_adrs);

            // Compute authentication path using fors_tree_node_to
            let mut auth_adrs = *adrs;
            for j in 0..a {
                let sibling_in_tree = (idx >> j) ^ 1;
                fors_tree_node_to::<H>(
                    &mut chunk[n + j * n..n + (j + 1) * n],
                    sk_seed,
                    tree_idx,
                    sibling_in_tree,
                    j as u32,
                    pk_seed,
                    &mut auth_adrs,
                    t,
                );
            }
        });
}

/// Generate a FORS signature in parallel.
///
/// Parallelizes across K independent FORS trees.
pub fn fors_sign_parallel<H: HashSuite + Send + Sync>(
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = H::N;
    let mut sig = vec![0u8; k * (n + a * n)];
    fors_sign_parallel_to::<H>(&mut sig, md, sk_seed, pk_seed, adrs, k, a);
    sig
}

/// Compute FORS public key from signature in parallel.
pub fn fors_pk_from_sig_parallel<H: HashSuite + Send + Sync>(
    sig_fors: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = H::N;
    let t = 1u32 << a;

    // Extract indices from message digest
    let indices = base_2b(md, a, k);

    let sig_elem_size = n + a * n;

    // Pre-allocate buffer for all roots and compute directly into it
    let mut all_roots = vec![0u8; k * n];
    all_roots
        .par_chunks_mut(n)
        .enumerate()
        .for_each(|(i, root_chunk)| {
            let sig_i = &sig_fors[i * sig_elem_size..(i + 1) * sig_elem_size];
            let sk = &sig_i[..n];
            let auth = &sig_i[n..];

            let idx = indices[i];
            let tree_idx = i as u32;
            let global_leaf_idx = tree_idx * t + idx;

            // Compute leaf from secret key using stack buffers
            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AdrsType::ForsTree);
            tree_adrs.set_tree_height(0);
            tree_adrs.set_tree_index(global_leaf_idx);
            let mut node = [0u8; 32];
            let mut tmp = [0u8; 32];
            H::f_to(&mut node[..n], pk_seed, &tree_adrs, sk);

            // Climb the tree using authentication path
            for j in 0..a {
                let auth_j = &auth[j * n..(j + 1) * n];

                let parent_in_tree = idx >> (j + 1);
                let nodes_at_parent_level = t >> (j + 1);
                let global_parent_idx = tree_idx * nodes_at_parent_level + parent_in_tree;

                tree_adrs.set_tree_height((j + 1) as u32);
                tree_adrs.set_tree_index(global_parent_idx);

                if (idx >> j) & 1 == 0 {
                    H::h_to(&mut tmp[..n], pk_seed, &tree_adrs, &node[..n], auth_j);
                } else {
                    H::h_to(&mut tmp[..n], pk_seed, &tree_adrs, auth_j, &node[..n]);
                }
                node[..n].copy_from_slice(&tmp[..n]);
            }

            root_chunk.copy_from_slice(&node[..n]);
        });

    let fors_pk_adrs = adrs.with_type(AdrsType::ForsPk);
    H::t_l(pk_seed, &fors_pk_adrs, &all_roots)
}

// ============================================================================
// XMSS Parallel Implementation
// ============================================================================

/// Compute a node in the XMSS Merkle tree with parallelization.
///
/// Uses parallel computation for left/right subtrees when depth allows.
pub fn xmss_node_parallel<H: HashSuite + Send + Sync, const WOTS_LEN: usize>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &Address,
) -> Vec<u8> {
    let n = H::N;

    if z == 0 {
        // Leaf node: compute WOTS+ public key (already parallelized)
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(AdrsType::WotsHash);
        leaf_adrs.set_keypair(i);
        wots_pk_gen_parallel::<H, WOTS_LEN>(sk_seed, pk_seed, &mut leaf_adrs)
    } else if z <= 2 {
        // Small subtrees: compute sequentially using buffer variant
        let mut node = [0u8; 32];
        xmss_node_to::<H, WOTS_LEN>(&mut node[..n], sk_seed, i, z, pk_seed, adrs);
        let result = node[..n].to_vec();
        node.zeroize();
        result
    } else {
        // Large subtrees: parallelize left and right (rayon::join requires owned values)
        let (left, right) = rayon::join(
            || xmss_node_parallel::<H, WOTS_LEN>(sk_seed, 2 * i, z - 1, pk_seed, adrs),
            || xmss_node_parallel::<H, WOTS_LEN>(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs),
        );

        let mut node_adrs = *adrs;
        node_adrs.set_type(AdrsType::Tree);
        node_adrs.set_tree_height(z);
        node_adrs.set_tree_index(i);
        let mut result = vec![0u8; n];
        H::h_to(&mut result, pk_seed, &node_adrs, &left, &right);
        result
    }
}

/// Generate an XMSS signature with parallel computation into a pre-allocated buffer.
pub fn xmss_sign_parallel_to<
    H: HashSuite + Send + Sync,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
>(
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

    // Generate WOTS+ signature (parallelized) directly into output buffer
    let mut wots_adrs = *adrs;
    wots_adrs.set_type(AdrsType::WotsHash);
    wots_adrs.set_keypair(idx);
    wots_sign_parallel_to::<H, WOTS_LEN, WOTS_LEN1>(
        &mut out[..wots_sig_len],
        message,
        sk_seed,
        pk_seed,
        &mut wots_adrs,
    );

    // Compute authentication path in parallel directly into output buffer
    out[wots_sig_len..]
        .par_chunks_mut(n)
        .enumerate()
        .for_each(|(j, chunk)| {
            let sibling_idx = (idx >> j) ^ 1;
            let node =
                xmss_node_parallel::<H, WOTS_LEN>(sk_seed, sibling_idx, j as u32, pk_seed, adrs);
            chunk.copy_from_slice(&node);
        });
}

/// Generate an XMSS signature with parallel authentication path computation.
pub fn xmss_sign_parallel<
    H: HashSuite + Send + Sync,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
>(
    message: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &Address,
    h_prime: usize,
) -> Vec<u8> {
    let n = H::N;
    let mut sig = vec![0u8; WOTS_LEN * n + h_prime * n];
    xmss_sign_parallel_to::<H, WOTS_LEN, WOTS_LEN1>(
        &mut sig, message, sk_seed, idx, pk_seed, adrs, h_prime,
    );
    sig
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;
    const K: usize = 4;
    const A: usize = 3;

    #[test]
    fn test_parallel_wots_pk_gen_matches_sequential() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];

        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);

        let pk_seq =
            crate::wots::wots_pk_gen::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs1);
        let pk_par = wots_pk_gen_parallel::<Shake128Hash, WOTS_LEN>(&sk_seed, &pk_seed, &mut adrs2);

        assert_eq!(pk_seq, pk_par);
    }

    #[test]
    fn test_parallel_wots_sign_matches_sequential() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let message = [3u8; N];

        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);

        let sig_seq = crate::wots::wots_sign::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, &mut adrs1,
        );
        let sig_par = wots_sign_parallel::<Shake128Hash, WOTS_LEN, WOTS_LEN1>(
            &message, &sk_seed, &pk_seed, &mut adrs2,
        );

        assert_eq!(sig_seq, sig_par);
    }

    #[test]
    fn test_parallel_fors_sign_matches_sequential() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let md = [0x55u8; 8];

        let mut adrs1 = Address::fors_tree(0, 0, 0, 0, 0);
        let adrs2 = Address::fors_tree(0, 0, 0, 0, 0);

        let sig_seq =
            crate::fors::fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut adrs1, K, A);
        let sig_par = fors_sign_parallel::<Shake128Hash>(&md, &sk_seed, &pk_seed, &adrs2, K, A);

        assert_eq!(sig_seq, sig_par);
    }

    #[test]
    fn test_parallel_fors_pk_from_sig_matches_sequential() {
        let sk_seed = [1u8; N];
        let pk_seed = [2u8; N];
        let md = [0x55u8; 8];

        let mut sign_adrs = Address::fors_tree(0, 0, 0, 0, 0);
        let sig =
            crate::fors::fors_sign::<Shake128Hash>(&md, &sk_seed, &pk_seed, &mut sign_adrs, K, A);

        let mut adrs1 = Address::fors_tree(0, 0, 0, 0, 0);
        let adrs2 = Address::fors_tree(0, 0, 0, 0, 0);

        let pk_seq =
            crate::fors::fors_pk_from_sig::<Shake128Hash>(&sig, &md, &pk_seed, &mut adrs1, K, A);
        let pk_par = fors_pk_from_sig_parallel::<Shake128Hash>(&sig, &md, &pk_seed, &adrs2, K, A);

        assert_eq!(pk_seq, pk_par);
    }
}
