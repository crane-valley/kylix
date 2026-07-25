//! Core SLH-DSA signing algorithms.
//!
//! This module contains the main KeyGen, Sign, and Verify algorithms
//! as specified in FIPS 205.
//!
//! FIPS 205, Algorithms 20-22.

use crate::address::{Address, AdrsType};
use crate::hash::{HashSuite, MAX_M_DIGEST_BYTES, MAX_N};
use crate::hypertree::{ht_root, ht_sign_to, ht_verify};

// Use parallel versions for signing (where parallelization helps)
#[cfg(feature = "parallel")]
use crate::parallel::fors_sign_parallel_to;

// Always use sequential fors_pk_from_sig for verification
// (parallel overhead exceeds benefits for small workloads)
use crate::fors::fors_pk_from_sig_to;

#[cfg(not(feature = "parallel"))]
use crate::fors::fors_sign_to;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

// The `write_to` buffer-shape invariants below were `debug_assert_eq!`, i.e.
// compiled out in release builds. Both `SIZE` and `N` are const generics, so
// the check belongs at compile time instead.
//
// The associated-constant form is deliberate: inline `const { .. }` blocks are
// not available on the MSRV (1.75), and a `const _: () = ..` item inside a
// generic function cannot see the function's generic parameters.

/// Compile-time guard for the `write_to` output buffer shape.
struct BufferShape<const N: usize, const SIZE: usize>;

impl<const N: usize, const SIZE: usize> BufferShape<N, SIZE> {
    const IS_4N: () = assert!(SIZE == N * 4, "secret key buffer size must be 4*N");
    const IS_2N: () = assert!(SIZE == N * 2, "public key buffer size must be 2*N");
}

/// Secret key components.
///
/// Implements `Zeroize` and `ZeroizeOnDrop` so secret material is securely
/// erased from memory when the key is dropped. `ZeroizeOnDrop` is derived
/// rather than hand-rolled as a `Drop` impl so downstream code can rely on the
/// marker trait as a bound.
///
/// The fields are private: handing out `[u8; N]` copies of `sk_seed`/`sk_prf`
/// would put secret material outside the zeroize-on-drop guarantee. Use
/// [`write_to`](Self::write_to) or [`to_bytes`](Self::to_bytes) to serialize
/// and [`from_bytes`](Self::from_bytes) to reconstruct; the wire layout is
/// unchanged.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const N: usize> {
    /// Secret seed for key generation.
    sk_seed: [u8; N],
    /// Secret PRF key for randomness generation.
    sk_prf: [u8; N],
    /// Public seed.
    pk_seed: [u8; N],
    /// Public key root.
    pk_root: [u8; N],
}

impl<const N: usize> SecretKey<N> {
    /// Write the secret key to a fixed-size byte array.
    ///
    /// This avoids heap allocation by writing directly to the provided buffer.
    /// Layout: sk_seed || sk_prf || pk_seed || pk_root
    pub fn write_to<const SIZE: usize>(&self, out: &mut [u8; SIZE]) {
        let () = BufferShape::<N, SIZE>::IS_4N;
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
        let () = BufferShape::<N, SIZE>::IS_2N;
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
    let mut sk = SecretKey {
        sk_seed: [0u8; N],
        sk_prf: [0u8; N],
        pk_seed: [0u8; N],
        pk_root: [0u8; N],
    };
    rng.fill_bytes(&mut sk.sk_seed);
    rng.fill_bytes(&mut sk.sk_prf);
    rng.fill_bytes(&mut sk.pk_seed);

    let pk_root = ht_root::<H, WOTS_LEN>(&sk.sk_seed, &sk.pk_seed, H_PRIME, D);
    sk.pk_root.copy_from_slice(&pk_root);

    let pk = PublicKey {
        pk_seed: sk.pk_seed,
        pk_root: sk.pk_root,
    };
    (sk, pk)
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
    mut sk_seed: [u8; N],
    mut sk_prf: [u8; N],
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
    sk_seed.zeroize();
    sk_prf.zeroize();

    let pk = PublicKey { pk_seed, pk_root };

    (sk, pk)
}

fn scratch_slice<'a, const STACK_LEN: usize>(
    stack: &'a mut [u8; STACK_LEN],
    heap: &'a mut Vec<u8>,
    len: usize,
) -> &'a mut [u8] {
    if len <= STACK_LEN {
        &mut stack[..len]
    } else {
        heap.resize(len, 0);
        heap.as_mut_slice()
    }
}

fn digest_lengths<const K: usize, const A: usize, const H_PRIME: usize, const D: usize>(
) -> (usize, usize) {
    let md_bytes = message_digest_bytes::<K, A>();
    let digest_len = md_bytes + (H_PRIME * (D - 1)).div_ceil(8) + H_PRIME.div_ceil(8);
    (md_bytes, digest_len)
}

fn message_digest_bytes<const K: usize, const A: usize>() -> usize {
    (K * A).div_ceil(8)
}

fn fors_signature_len<const N: usize, const K: usize, const A: usize>() -> usize {
    K * (A + 1) * N
}

fn hypertree_signature_len<
    const N: usize,
    const WOTS_LEN: usize,
    const H_PRIME: usize,
    const D: usize,
>() -> usize {
    D * (WOTS_LEN * N + H_PRIME * N)
}

fn signature_lengths<
    const N: usize,
    const WOTS_LEN: usize,
    const H_PRIME: usize,
    const D: usize,
    const K: usize,
    const A: usize,
>() -> (usize, usize) {
    let fors_sig_len = fors_signature_len::<N, K, A>();
    let sig_len = N + fors_sig_len + hypertree_signature_len::<N, WOTS_LEN, H_PRIME, D>();
    (fors_sig_len, sig_len)
}

fn fors_tree_address(idx_tree: u64, idx_leaf: u32) -> Address {
    let mut adrs = Address::new();
    adrs.set_type(AdrsType::ForsTree);
    adrs.set_tree(idx_tree);
    adrs.set_keypair(idx_leaf);
    adrs
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
    slh_sign_with_prefix::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
        sk,
        &[],
        message,
        opt_rand,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "parallel")]
pub(crate) fn slh_sign_with_prefix<
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
    message_prefix: &[u8],
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    slh_sign_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
        sk,
        message_prefix,
        message,
        opt_rand,
    )
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
    slh_sign_with_prefix::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
        sk,
        &[],
        message,
        opt_rand,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "parallel"))]
pub(crate) fn slh_sign_with_prefix<
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
    message_prefix: &[u8],
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    slh_sign_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A, MD_BYTES>(
        sk,
        message_prefix,
        message,
        opt_rand,
    )
}

/// Hash-suite bound required by the signing body.
///
/// The parallel FORS backend needs `Send + Sync`, the sequential one does not.
/// Selecting the bound here lets a single `slh_sign_impl` body serve both
/// feature arms. The public wrappers keep their own spelled-out bounds, which
/// are part of the public API and must not be unified.
#[cfg(feature = "parallel")]
trait SignHashSuite: HashSuite + Send + Sync {}

#[cfg(feature = "parallel")]
impl<H: HashSuite + Send + Sync> SignHashSuite for H {}

#[cfg(not(feature = "parallel"))]
trait SignHashSuite: HashSuite {}

#[cfg(not(feature = "parallel"))]
impl<H: HashSuite> SignHashSuite for H {}

/// FORS signing step of `slh_sign_impl`.
///
/// Takes `adrs` by shared reference in both arms: the sequential backend
/// mutates the address it is given, so that mutation is confined to a local
/// copy here and the caller regenerates the address for FORS pk recovery. This
/// keeps the byte output of the two arms identical.
fn fors_sign_dispatch<H: SignHashSuite>(
    out: &mut [u8],
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    k: usize,
    a: usize,
) {
    #[cfg(feature = "parallel")]
    fors_sign_parallel_to::<H>(out, md, sk_seed, pk_seed, adrs, k, a);

    #[cfg(not(feature = "parallel"))]
    {
        let mut adrs = *adrs;
        fors_sign_to::<H>(out, md, sk_seed, pk_seed, &mut adrs, k, a);
    }
}

#[allow(clippy::too_many_arguments)]
fn slh_sign_impl<
    H: SignHashSuite,
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
    message_prefix: &[u8],
    message: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    // Use pk_seed as opt_rand for deterministic signing if not provided
    let randomness = opt_rand.unwrap_or(&sk.pk_seed);

    // Generate randomness R
    let mut r = Zeroizing::new([0u8; MAX_N]);
    H::prf_msg_parts_to(&mut r[..N], &sk.sk_prf, randomness, message_prefix, message);

    let (md_bytes, digest_len) = digest_lengths::<K, A, H_PRIME, D>();

    // Compute message digest
    let mut digest_stack = [0u8; MAX_M_DIGEST_BYTES];
    let mut digest_heap = Vec::new();
    let digest = scratch_slice(&mut digest_stack, &mut digest_heap, digest_len);
    H::h_msg_parts_to(
        digest,
        &r[..N],
        &sk.pk_seed,
        &sk.pk_root,
        message_prefix,
        message,
    );

    // Parse digest into (md, idx_tree, idx_leaf)
    let mut md_stack = [0u8; MAX_M_DIGEST_BYTES];
    let mut md_heap = Vec::new();
    let md = scratch_slice(&mut md_stack, &mut md_heap, md_bytes);
    let (md_len, idx_tree, idx_leaf) = parse_digest_to::<K, A, H_PRIME, D>(md, digest);

    let adrs = fors_tree_address(idx_tree, idx_leaf);

    // Pre-allocate single signature buffer: R || SIG_FORS || SIG_HT
    let (fors_sig_len, sig_len) = signature_lengths::<N, WOTS_LEN, H_PRIME, D, K, A>();
    let mut signature = vec![0u8; sig_len];

    // Write R
    signature[..N].copy_from_slice(&r[..N]);

    // Generate FORS signature directly into buffer
    fors_sign_dispatch::<H>(
        &mut signature[N..N + fors_sig_len],
        &md[..md_len],
        &sk.sk_seed,
        &sk.pk_seed,
        &adrs,
        K,
        A,
    );

    // Compute FORS public key for hypertree signing.
    // Always sequential: pk recovery is fast and parallel overhead hurts.
    // The address is regenerated rather than reused so both FORS backends see
    // the same input regardless of whether they mutated their own copy.
    let mut adrs_pk = fors_tree_address(idx_tree, idx_leaf);
    let mut pk_fors = [0u8; MAX_N];
    fors_pk_from_sig_to::<H>(
        &mut pk_fors[..N],
        &signature[N..N + fors_sig_len],
        &md[..md_len],
        &sk.pk_seed,
        &mut adrs_pk,
        K,
        A,
    );

    // Generate hypertree signature directly into buffer
    ht_sign_to::<H, WOTS_LEN, WOTS_LEN1>(
        &mut signature[N + fors_sig_len..],
        &pk_fors[..N],
        &sk.sk_seed,
        &sk.pk_seed,
        idx_tree,
        idx_leaf,
        H_PRIME,
        D,
    );

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
    slh_verify_with_prefix::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
        pk,
        &[],
        message,
        signature,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn slh_verify_with_prefix<
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
    message_prefix: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    slh_verify_impl::<H, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
        pk,
        message_prefix,
        message,
        signature,
    )
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
    message_prefix: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    // Calculate expected signature size
    let (fors_sig_len, expected_sig_len) = signature_lengths::<N, WOTS_LEN, H_PRIME, D, K, A>();

    if signature.len() != expected_sig_len {
        return false;
    }

    // Parse signature: R || SIG_FORS || SIG_HT
    let r = &signature[..N];
    let sig_fors = &signature[N..N + fors_sig_len];
    let sig_ht = &signature[N + fors_sig_len..];

    let (md_bytes, digest_len) = digest_lengths::<K, A, H_PRIME, D>();

    // Compute message digest
    let mut digest_stack = [0u8; MAX_M_DIGEST_BYTES];
    let mut digest_heap = Vec::new();
    let digest = scratch_slice(&mut digest_stack, &mut digest_heap, digest_len);
    H::h_msg_parts_to(digest, r, &pk.pk_seed, &pk.pk_root, message_prefix, message);

    // Parse digest into (md, idx_tree, idx_leaf)
    let mut md_stack = [0u8; MAX_M_DIGEST_BYTES];
    let mut md_heap = Vec::new();
    let md = scratch_slice(&mut md_stack, &mut md_heap, md_bytes);
    let (md_len, idx_tree, idx_leaf) = parse_digest_to::<K, A, H_PRIME, D>(md, digest);

    let mut adrs = fors_tree_address(idx_tree, idx_leaf);

    // Recover FORS public key from signature (sequential)
    let mut pk_fors = [0u8; MAX_N];
    fors_pk_from_sig_to::<H>(
        &mut pk_fors[..N],
        sig_fors,
        &md[..md_len],
        &pk.pk_seed,
        &mut adrs,
        K,
        A,
    );

    // Verify hypertree signature
    ht_verify::<H, WOTS_LEN, WOTS_LEN1>(
        &pk_fors[..N],
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
fn parse_digest_to<const K: usize, const A: usize, const H_PRIME: usize, const D: usize>(
    md_out: &mut [u8],
    digest: &[u8],
) -> (usize, u64, u32) {
    // Calculate bit positions
    let tree_bits = H_PRIME * (D - 1); // Total height - h' for bottom layer
    let leaf_bits = H_PRIME;

    // Calculate byte boundaries
    let md_bytes = message_digest_bytes::<K, A>();
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bytes = leaf_bits.div_ceil(8);

    // Extract message digest for FORS (first md_bytes)
    md_out[..md_bytes].copy_from_slice(&digest[..md_bytes]);

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

    (md_bytes, idx_tree, idx_leaf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// Golden test pinning the SecretKey wire layout to
    /// sk_seed || sk_prf || pk_seed || pk_root, so a future change to the
    /// struct (field privacy, reordering, added accessors) cannot silently
    /// alter the bytes that to_bytes/from_bytes/write_to produce and accept.
    #[test]
    fn test_secret_key_golden_byte_layout() {
        const SK_SEED: [u8; N] = [0xA1; N];
        const SK_PRF: [u8; N] = [0xB2; N];
        const PK_SEED: [u8; N] = [0xC3; N];
        const PK_ROOT: [u8; N] = [0xD4; N];

        let mut golden = [0u8; 4 * N];
        golden[..N].copy_from_slice(&SK_SEED);
        golden[N..2 * N].copy_from_slice(&SK_PRF);
        golden[2 * N..3 * N].copy_from_slice(&PK_SEED);
        golden[3 * N..].copy_from_slice(&PK_ROOT);

        let sk = SecretKey::<N>::from_bytes(&golden).expect("golden length is 4*N");
        assert_eq!(sk.sk_seed, SK_SEED);
        assert_eq!(sk.sk_prf, SK_PRF);
        assert_eq!(sk.pk_seed, PK_SEED);
        assert_eq!(sk.pk_root, PK_ROOT);

        assert_eq!(&sk.to_bytes()[..], &golden[..]);

        let mut written = [0u8; 4 * N];
        sk.write_to(&mut written);
        assert_eq!(written, golden);

        assert!(SecretKey::<N>::from_bytes(&golden[..4 * N - 1]).is_none());
        assert!(SecretKey::<N>::from_bytes(&[0u8; 4 * N + 1]).is_none());
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
    fn test_sign_verify_roundtrip_with_heap_backed_scratch() {
        const BIG_WOTS_LEN: usize = 68;
        const BIG_WOTS_LEN1: usize = BIG_WOTS_LEN;
        const BIG_H_PRIME: usize = 2;
        const BIG_D: usize = 2;
        const BIG_K: usize = 50;
        const BIG_A: usize = 8;
        const BIG_MD_BYTES: usize = 50;

        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (sk, pk) = slh_keygen::<Shake128Hash, N, BIG_WOTS_LEN, BIG_H_PRIME, BIG_D>(&mut rng);
        let message = b"Exercises heap-backed scratch";

        let signature = slh_sign::<
            Shake128Hash,
            N,
            BIG_WOTS_LEN,
            BIG_WOTS_LEN1,
            BIG_H_PRIME,
            BIG_D,
            BIG_K,
            BIG_A,
            BIG_MD_BYTES,
        >(&sk, message, None);

        let valid = slh_verify::<
            Shake128Hash,
            N,
            BIG_WOTS_LEN,
            BIG_WOTS_LEN1,
            BIG_H_PRIME,
            BIG_D,
            BIG_K,
            BIG_A,
        >(&pk, message, &signature);

        assert!(valid, "Heap-backed scratch roundtrip failed");
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
        let (_, expected_size) = signature_lengths::<N, WOTS_LEN, H_PRIME, D, K, A>();

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
        let mut md = [0u8; MAX_M_DIGEST_BYTES];
        let (md_len, idx_tree, idx_leaf) = parse_digest_to::<K, A, H_PRIME, D>(&mut md, &digest);

        // md should be first ceil(k*a/8) = ceil(12/8) = 2 bytes
        assert_eq!(md_len, 2);
        assert_eq!(&md[..md_len], &[0x12, 0x34]);

        // tree_bits = H_PRIME * (D - 1) = 3 * 1 = 3 bits, so 1 byte
        // idx_tree should be masked to 3 bits
        assert!(idx_tree < 8, "idx_tree should be < 2^3");

        // leaf_bits = H_PRIME = 3 bits
        // idx_leaf should be masked to 3 bits
        assert!(idx_leaf < 8, "idx_leaf should be < 2^3");
    }
}
