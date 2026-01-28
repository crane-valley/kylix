//! Core SLH-DSA signing algorithms.
//!
//! This module contains the main KeyGen, Sign, and Verify algorithms
//! as specified in FIPS 205.
//!
//! FIPS 205, Algorithms 20-22.

use crate::address::{Address, AdrsType};
use crate::hash::HashSuite;
use crate::hypertree::{ht_root, ht_sign, ht_verify};

// Use parallel versions for signing (where parallelization helps)
#[cfg(feature = "parallel")]
use crate::parallel::fors_sign_parallel;

// Always use sequential fors_pk_from_sig for verification
// (parallel overhead exceeds benefits for small workloads)
use crate::fors::fors_pk_from_sig;

#[cfg(not(feature = "parallel"))]
use crate::fors::fors_sign;

use rand_core::CryptoRng;
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Secret key components.
///
/// Implements `Zeroize` via derive and manual `Drop` to ensure secret material
/// is securely erased from memory when the key is dropped.
#[derive(Clone, Zeroize)]
pub struct SecretKey<const N: usize> {
    /// Secret seed for key generation.
    pub sk_seed: [u8; N],
    /// Secret PRF key for randomness generation.
    pub sk_prf: [u8; N],
    /// Public seed.
    pub pk_seed: [u8; N],
    /// Public key root.
    pub pk_root: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    /// Write the secret key to a fixed-size byte array.
    ///
    /// This avoids heap allocation by writing directly to the provided buffer.
    /// Layout: sk_seed || sk_prf || pk_seed || pk_root
    pub fn write_to<const SIZE: usize>(&self, out: &mut [u8; SIZE]) {
        debug_assert_eq!(SIZE, N * 4, "Output buffer size must be 4*N");
        out[..N].copy_from_slice(&self.sk_seed);
        out[N..2 * N].copy_from_slice(&self.sk_prf);
        out[2 * N..3 * N].copy_from_slice(&self.pk_seed);
        out[3 * N..].copy_from_slice(&self.pk_root);
    }

    /// Serialize the secret key to bytes.
    ///
    /// Note: This method copies secret material to a new Vec.
    /// The returned Vec should be zeroized after use.
    /// Prefer `write_to` when possible to avoid heap allocation.
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(N * 4));
        bytes.extend_from_slice(&self.sk_seed);
        bytes.extend_from_slice(&self.sk_prf);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Deserialize a secret key from bytes.
    ///
    /// Writes directly into struct fields to avoid intermediate buffers
    /// that would need manual zeroization.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * 4 {
            return None;
        }
        // Initialize struct with zeroed arrays, then copy directly into fields
        // This avoids intermediate stack buffers for sensitive data
        let mut key = Self {
            sk_seed: [0u8; N],
            sk_prf: [0u8; N],
            pk_seed: [0u8; N],
            pk_root: [0u8; N],
        };
        key.sk_seed.copy_from_slice(&bytes[..N]);
        key.sk_prf.copy_from_slice(&bytes[N..2 * N]);
        key.pk_seed.copy_from_slice(&bytes[2 * N..3 * N]);
        key.pk_root.copy_from_slice(&bytes[3 * N..]);
        Some(key)
    }
}

impl<const N: usize> Drop for SecretKey<N> {
    fn drop(&mut self) {
        // Zeroize all fields using the derived Zeroize impl
        self.zeroize();
    }
}

/// Public key components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<const N: usize> {
    /// Public seed.
    pub pk_seed: [u8; N],
    /// Public key root.
    pub pk_root: [u8; N],
}

impl<const N: usize> PublicKey<N> {
    /// Write the public key to a fixed-size byte array.
    ///
    /// This avoids heap allocation by writing directly to the provided buffer.
    /// Layout: pk_seed || pk_root
    pub fn write_to<const SIZE: usize>(&self, out: &mut [u8; SIZE]) {
        debug_assert_eq!(SIZE, N * 2, "Output buffer size must be 2*N");
        out[..N].copy_from_slice(&self.pk_seed);
        out[N..].copy_from_slice(&self.pk_root);
    }

    /// Serialize the public key to bytes.
    ///
    /// Prefer `write_to` when possible to avoid heap allocation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(N * 2);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * 2 {
            return None;
        }
        let mut pk_seed = [0u8; N];
        let mut pk_root = [0u8; N];
        pk_seed.copy_from_slice(&bytes[..N]);
        pk_root.copy_from_slice(&bytes[N..]);
        Some(Self { pk_seed, pk_root })
    }
}

/// Generate an SLH-DSA key pair.
///
/// FIPS 205, Algorithm 20: slh_keygen()
///
/// # Type Parameters
/// * `H` - Hash suite
/// * `N` - Security parameter (hash output size)
/// * `WOTS_LEN` - WOTS+ signature length
/// * `H_PRIME` - XMSS tree height
/// * `D` - Number of hypertree layers
///
/// # Arguments
/// * `rng` - Random number generator
///
/// # Returns
/// (SecretKey, PublicKey) tuple
pub fn slh_keygen<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const H_PRIME: usize,
    const D: usize,
>(
    rng: &mut impl CryptoRng,
) -> (SecretKey<N>, PublicKey<N>) {
    let mut sk_seed = [0u8; N];
    let mut sk_prf = [0u8; N];
    let mut pk_seed = [0u8; N];

    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    slh_keygen_internal::<H, N, WOTS_LEN, H_PRIME, D>(sk_seed, sk_prf, pk_seed)
}

/// Internal key generation with deterministic seeds.
///
/// This is used for ACVP testing where seeds are provided directly.
///
/// # Type Parameters
/// * `H` - Hash suite
/// * `N` - Security parameter (hash output size)
/// * `WOTS_LEN` - WOTS+ signature length
/// * `H_PRIME` - XMSS tree height
/// * `D` - Number of hypertree layers
///
/// # Arguments
/// * `sk_seed` - Secret seed for key generation
/// * `sk_prf` - Secret PRF key for randomness generation
/// * `pk_seed` - Public seed
///
/// # Returns
/// (SecretKey, PublicKey) tuple
pub fn slh_keygen_internal<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const H_PRIME: usize,
    const D: usize,
>(
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
) -> (SecretKey<N>, PublicKey<N>) {
    // Compute pk_root using hypertree
    let pk_root_vec = ht_root::<H, WOTS_LEN>(&sk_seed, &pk_seed, H_PRIME, D);
    let mut pk_root = [0u8; N];
    pk_root.copy_from_slice(&pk_root_vec);

    let sk = SecretKey {
        sk_seed,
        sk_prf,
        pk_seed,
        pk_root,
    };

    let pk = PublicKey { pk_seed, pk_root };

    (sk, pk)
}

/// Sign a message using SLH-DSA.
///
/// FIPS 205, Algorithm 21: slh_sign(M, SK)
///
/// # Type Parameters
/// * `H` - Hash suite
/// * `N` - Security parameter
/// * `WOTS_LEN` - WOTS+ signature length
/// * `WOTS_LEN1` - WOTS+ len1 parameter
/// * `H_PRIME` - XMSS tree height
/// * `D` - Number of hypertree layers
/// * `K` - Number of FORS trees
/// * `A` - FORS tree height
/// * `MD_BYTES` - Message digest bytes
///
/// # Arguments
/// * `sk` - Secret key
/// * `message` - Message to sign
/// * `opt_rand` - Optional randomness (if None, uses pk_seed for deterministic signing)
///
/// # Returns
/// Signature bytes
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "parallel")]
pub fn slh_sign<
    H: HashSuite + Send + Sync,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
    const MD_BYTES: usize,
>(
    sk: &SecretKey<N>,
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    slh_sign_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(sk, message, opt_rand)
}

/// Sign a message using SLH-DSA (sequential version).
#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "parallel"))]
pub fn slh_sign<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
    const MD_BYTES: usize,
>(
    sk: &SecretKey<N>,
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    slh_sign_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(sk, message, opt_rand)
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "parallel")]
fn slh_sign_impl<
    H: HashSuite + Send + Sync,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
    const MD_BYTES: usize,
>(
    sk: &SecretKey<N>,
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    // Use pk_seed as opt_rand for deterministic signing if not provided
    let randomness = opt_rand.unwrap_or(&sk.pk_seed);

    // Generate randomness R
    let r = H::prf_msg(&sk.sk_prf, randomness, message);

    // Calculate digest length: need enough bytes for md || idx_tree || idx_leaf
    // md: K*A bits, idx_tree: H_PRIME*(D-1) bits, idx_leaf: H_PRIME bits
    let md_bytes = (K * A).div_ceil(8);
    let tree_bits = H_PRIME * (D - 1);
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bytes = H_PRIME.div_ceil(8);
    let digest_len = md_bytes + tree_bytes + leaf_bytes;

    // Compute message digest
    let digest = H::h_msg(&r, &sk.pk_seed, &sk.pk_root, message, digest_len);

    // Parse digest into (md, idx_tree, idx_leaf)
    let (md, idx_tree, idx_leaf) = parse_digest::<K, A, H_PRIME, D>(&digest);

    // Set up FORS address
    let adrs = {
        let mut a = Address::new();
        a.set_type(AdrsType::ForsTree);
        a.set_tree(idx_tree);
        a.set_keypair(idx_leaf);
        a
    };

    // Generate FORS signature (parallel - this is the expensive part)
    let sig_fors = fors_sign_parallel::<H>(&md, &sk.sk_seed, &sk.pk_seed, &adrs, K, A);

    // Compute FORS public key for hypertree signing
    // Use sequential version - pk recovery is fast and parallel overhead hurts
    let mut adrs_pk = adrs;
    let pk_fors = fors_pk_from_sig::<H>(&sig_fors, &md, &sk.pk_seed, &mut adrs_pk, K, A);

    // Generate hypertree signature
    let sig_ht = ht_sign::<H, WOTS_LEN, WOTS_LEN1>(
        &pk_fors,
        &sk.sk_seed,
        &sk.pk_seed,
        idx_tree,
        idx_leaf,
        H_PRIME,
        D,
    );

    // Assemble signature: R || SIG_FORS || SIG_HT
    let mut signature = Vec::with_capacity(N + sig_fors.len() + sig_ht.len());
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&sig_fors);
    signature.extend_from_slice(&sig_ht);

    signature
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "parallel"))]
fn slh_sign_impl<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
    const MD_BYTES: usize,
>(
    sk: &SecretKey<N>,
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    // Use pk_seed as opt_rand for deterministic signing if not provided
    let randomness = opt_rand.unwrap_or(&sk.pk_seed);

    // Generate randomness R
    let r = H::prf_msg(&sk.sk_prf, randomness, message);

    // Calculate digest length: need enough bytes for md || idx_tree || idx_leaf
    // md: K*A bits, idx_tree: H_PRIME*(D-1) bits, idx_leaf: H_PRIME bits
    let md_bytes = (K * A).div_ceil(8);
    let tree_bits = H_PRIME * (D - 1);
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bytes = H_PRIME.div_ceil(8);
    let digest_len = md_bytes + tree_bytes + leaf_bytes;

    // Compute message digest
    let digest = H::h_msg(&r, &sk.pk_seed, &sk.pk_root, message, digest_len);

    // Parse digest into (md, idx_tree, idx_leaf)
    let (md, idx_tree, idx_leaf) = parse_digest::<K, A, H_PRIME, D>(&digest);

    // Set up FORS address
    let mut adrs = Address::new();
    adrs.set_type(AdrsType::ForsTree);
    adrs.set_tree(idx_tree);
    adrs.set_keypair(idx_leaf);

    // Generate FORS signature (sequential)
    let sig_fors = fors_sign::<H>(&md, &sk.sk_seed, &sk.pk_seed, &mut adrs, K, A);

    // Compute FORS public key for hypertree signing (sequential)
    let mut adrs_pk = Address::new();
    adrs_pk.set_type(AdrsType::ForsTree);
    adrs_pk.set_tree(idx_tree);
    adrs_pk.set_keypair(idx_leaf);
    let pk_fors = fors_pk_from_sig::<H>(&sig_fors, &md, &sk.pk_seed, &mut adrs_pk, K, A);

    // Generate hypertree signature
    let sig_ht = ht_sign::<H, WOTS_LEN, WOTS_LEN1>(
        &pk_fors,
        &sk.sk_seed,
        &sk.pk_seed,
        idx_tree,
        idx_leaf,
        H_PRIME,
        D,
    );

    // Assemble signature: R || SIG_FORS || SIG_HT
    let mut signature = Vec::with_capacity(N + sig_fors.len() + sig_ht.len());
    signature.extend_from_slice(&r);
    signature.extend_from_slice(&sig_fors);
    signature.extend_from_slice(&sig_ht);

    signature
}

/// Verify an SLH-DSA signature.
///
/// FIPS 205, Algorithm 22: slh_verify(M, SIG, PK)
///
/// Note: Verification always uses the sequential implementation because
/// the parallel overhead exceeds benefits for this fast operation.
///
/// # Type Parameters
/// * `H` - Hash suite
/// * `N` - Security parameter
/// * `WOTS_LEN` - WOTS+ signature length
/// * `WOTS_LEN1` - WOTS+ len1 parameter
/// * `H_PRIME` - XMSS tree height
/// * `D` - Number of hypertree layers
/// * `K` - Number of FORS trees
/// * `A` - FORS tree height
///
/// # Arguments
/// * `pk` - Public key
/// * `message` - Original message
/// * `signature` - Signature to verify
///
/// # Returns
/// true if signature is valid
#[allow(clippy::too_many_arguments)]
pub fn slh_verify<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
>(
    pk: &PublicKey<N>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    slh_verify_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(pk, message, signature)
}

// Unified verify implementation - always uses sequential FORS pk recovery
// because parallel overhead exceeds benefits for this fast operation.
#[allow(clippy::too_many_arguments)]
fn slh_verify_impl<
    H: HashSuite,
    const N: usize,
    const WOTS_LEN: usize,
    const WOTS_LEN1: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
>(
    pk: &PublicKey<N>,
    message: &[u8],
    signature: &[u8],
) -> bool {
    // Calculate expected signature size
    let fors_sig_len = K * (A + 1) * N;
    let ht_sig_len = D * (WOTS_LEN * N + H_PRIME * N);
    let expected_sig_len = N + fors_sig_len + ht_sig_len;

    if signature.len() != expected_sig_len {
        return false;
    }

    // Parse signature: R || SIG_FORS || SIG_HT
    let r = &signature[..N];
    let sig_fors = &signature[N..N + fors_sig_len];
    let sig_ht = &signature[N + fors_sig_len..];

    // Calculate digest length: need enough bytes for md || idx_tree || idx_leaf
    let md_bytes = (K * A).div_ceil(8);
    let tree_bits = H_PRIME * (D - 1);
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bytes = H_PRIME.div_ceil(8);
    let digest_len = md_bytes + tree_bytes + leaf_bytes;

    // Compute message digest
    let digest = H::h_msg(r, &pk.pk_seed, &pk.pk_root, message, digest_len);

    // Parse digest into (md, idx_tree, idx_leaf)
    let (md, idx_tree, idx_leaf) = parse_digest::<K, A, H_PRIME, D>(&digest);

    // Set up FORS address
    let mut adrs = Address::new();
    adrs.set_type(AdrsType::ForsTree);
    adrs.set_tree(idx_tree);
    adrs.set_keypair(idx_leaf);

    // Recover FORS public key from signature (sequential)
    let pk_fors = fors_pk_from_sig::<H>(sig_fors, &md, &pk.pk_seed, &mut adrs, K, A);

    // Verify hypertree signature
    ht_verify::<H, WOTS_LEN, WOTS_LEN1>(
        &pk_fors,
        sig_ht,
        &pk.pk_seed,
        idx_tree,
        idx_leaf,
        &pk.pk_root,
        H_PRIME,
        D,
    )
}

/// Parse digest into FORS message digest, tree index, and leaf index.
///
/// FIPS 205, Section 9.2: The digest is split at byte boundaries:
/// - First ceil(k*a/8) bytes: FORS message digest (md)
/// - Next ceil(h'*(d-1)/8) bytes: Tree index (idx_tree)
/// - Next ceil(h'/8) bytes: Leaf index (idx_leaf)
///
/// The tree and leaf indices are masked to their respective bit widths.
fn parse_digest<const K: usize, const A: usize, const H_PRIME: usize, const D: usize>(
    digest: &[u8],
) -> (Vec<u8>, u64, u32) {
    // Calculate bit positions
    let md_bits = K * A;
    let tree_bits = H_PRIME * (D - 1); // Total height - h' for bottom layer
    let leaf_bits = H_PRIME;

    // Calculate byte boundaries
    let md_bytes = md_bits.div_ceil(8);
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bytes = leaf_bits.div_ceil(8);

    // Extract message digest for FORS (first md_bytes)
    let md = digest[..md_bytes].to_vec();

    // Extract tree index (next tree_bytes)
    let tree_start = md_bytes;
    let mut idx_tree: u64 = 0;
    for i in 0..tree_bytes {
        if tree_start + i < digest.len() {
            idx_tree = (idx_tree << 8) | (digest[tree_start + i] as u64);
        }
    }
    // Mask to tree_bits
    if tree_bits > 0 && tree_bits < 64 {
        idx_tree &= (1u64 << tree_bits) - 1;
    }

    // Extract leaf index (next leaf_bytes)
    let leaf_start = tree_start + tree_bytes;
    let mut idx_leaf: u32 = 0;
    for i in 0..leaf_bytes {
        if leaf_start + i < digest.len() {
            idx_leaf = (idx_leaf << 8) | (digest[leaf_start + i] as u32);
        }
    }
    // Mask to leaf_bits
    if leaf_bits > 0 && leaf_bits < 32 {
        idx_leaf &= (1u32 << leaf_bits) - 1;
    }

    (md, idx_tree, idx_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_shake::Shake128Hash;
    use alloc::vec;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Test parameters (smaller than real parameters for faster tests)
    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;
    const H_PRIME: usize = 3;
    const D: usize = 2;
    const K: usize = 4;
    const A: usize = 3;
    const MD_BYTES: usize = 8;

    #[test]
    fn test_keygen_determinism() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(42);
        let mut rng2 = ChaCha20Rng::seed_from_u64(42);

        let (sk1, pk1) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng1);
        let (sk2, pk2) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng2);

        assert_eq!(sk1.sk_seed, sk2.sk_seed);
        assert_eq!(sk1.pk_root, sk2.pk_root);
        assert_eq!(pk1.pk_seed, pk2.pk_seed);
        assert_eq!(pk1.pk_root, pk2.pk_root);
    }

    #[test]
    fn test_key_serialization() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        // Test secret key serialization
        let sk_bytes = sk.to_bytes();
        let sk_restored = SecretKey::<N>::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.sk_seed, sk_restored.sk_seed);
        assert_eq!(sk.sk_prf, sk_restored.sk_prf);
        assert_eq!(sk.pk_seed, sk_restored.pk_seed);
        assert_eq!(sk.pk_root, sk_restored.pk_root);

        // Test public key serialization
        let pk_bytes = pk.to_bytes();
        let pk_restored = PublicKey::<N>::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk_restored);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let message = b"Hello, SLH-DSA!";

        let signature = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );

        let valid = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
            &pk, message, &signature,
        );

        assert!(valid, "Signature verification failed");
    }

    #[test]
    fn test_sign_determinism() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, _pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let message = b"Test message";

        // Deterministic signing (using pk_seed as opt_rand)
        let sig1 = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );
        let sig2 = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );

        assert_eq!(
            sig1, sig2,
            "Deterministic signing should produce same signature"
        );
    }

    #[test]
    fn test_signature_size() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, _pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let message = b"Test message";
        let signature = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );

        // Expected size: N + K*(A+1)*N + D*(WOTS_LEN*N + H_PRIME*N)
        let fors_sig_len = K * (A + 1) * N;
        let ht_sig_len = D * (WOTS_LEN * N + H_PRIME * N);
        let expected_size = N + fors_sig_len + ht_sig_len;

        assert_eq!(signature.len(), expected_size);
    }

    #[test]
    fn test_wrong_message_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let message = b"Original message";
        let wrong_message = b"Modified message";

        let signature = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );

        let valid = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
            &pk,
            wrong_message,
            &signature,
        );

        assert!(!valid, "Verification should fail for wrong message");
    }

    #[test]
    fn test_wrong_signature_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let message = b"Test message";
        let mut signature =
            slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
                &sk, message, None,
            );

        // Corrupt the signature
        signature[10] ^= 0xFF;

        let valid = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
            &pk, message, &signature,
        );

        assert!(!valid, "Verification should fail for corrupted signature");
    }

    #[test]
    fn test_wrong_public_key_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, _pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        // Generate a different key pair
        let mut rng2 = ChaCha20Rng::seed_from_u64(99);
        let (_sk2, pk2) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng2);

        let message = b"Test message";
        let signature = slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
            &sk, message, None,
        );

        // Verify with wrong public key
        let valid = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
            &pk2, message, &signature,
        );

        assert!(!valid, "Verification should fail for wrong public key");
    }

    #[test]
    fn test_different_messages() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(&mut rng);

        let messages = [
            b"Message 1".as_slice(),
            b"Message 2".as_slice(),
            b"A longer message for testing".as_slice(),
            b"".as_slice(),
            &[0u8; 1000],
        ];

        for message in &messages {
            let signature =
                slh_sign::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
                    &sk, message, None,
                );

            let valid = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                &pk, message, &signature,
            );

            assert!(valid, "Failed for message of length {}", message.len());
        }
    }

    #[test]
    fn test_parse_digest() {
        let digest = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        ];
        let (md, idx_tree, idx_leaf) = parse_digest::<K, A, H_PRIME, D>(&digest);

        // md should be first ceil(k*a/8) = ceil(12/8) = 2 bytes
        assert_eq!(md.len(), 2);

        // tree_bits = H_PRIME * (D - 1) = 3 * 1 = 3 bits, so 1 byte
        // idx_tree should be masked to 3 bits
        assert!(idx_tree < 8, "idx_tree should be < 2^3");

        // leaf_bits = H_PRIME = 3 bits
        // idx_leaf should be masked to 3 bits
        assert!(idx_leaf < 8, "idx_leaf should be < 2^3");
    }
}
