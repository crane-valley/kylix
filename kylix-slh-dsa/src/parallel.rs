//! Parallel implementations of SLH-DSA building blocks.
//!
//! This module provides parallelized versions of the computationally intensive
//! operations in SLH-DSA using Rayon for multi-threading.
//!
//! Currently only FORS is parallelized: its K trees are independent.

use crate::address::{Address, AdrsType};
use crate::fors::fors_tree_node_to;
use crate::hash::HashSuite;
use crate::utils::base_2b;

use rayon::prelude::*;

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
