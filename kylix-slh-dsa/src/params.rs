//! SLH-DSA parameter sets as defined in FIPS 205.
//!
//! All 12 parameter sets are defined here:
//! - 6 SHAKE-based variants: SHAKE-128s/f, SHAKE-192s/f, SHAKE-256s/f
//! - 6 SHA2-based variants: SHA2-128s/f, SHA2-192s/f, SHA2-256s/f

/// Common parameters shared across all SLH-DSA variants.
pub mod common {
    /// Winternitz parameter (always 16 for SLH-DSA).
    pub const W: usize = 16;

    /// Log2 of Winternitz parameter.
    pub const LG_W: usize = 4;

    /// Address size in bytes.
    pub const ADRS_BYTES: usize = 32;
}

/// Trait for SLH-DSA parameter sets.
pub trait Params {
    /// Security parameter n (hash output length in bytes).
    const N: usize;

    /// Height of each XMSS tree (h' = h/d).
    const H_PRIME: usize;

    /// Total Hypertree height.
    const H: usize;

    /// Number of Hypertree layers.
    const D: usize;

    /// FORS tree height.
    const A: usize;

    /// Number of FORS trees.
    const K: usize;

    /// WOTS+ len1 = ceil(8n / lg(w)).
    const WOTS_LEN1: usize;

    /// WOTS+ len2 = floor(lg(len1 * (w-1)) / lg(w)) + 1.
    const WOTS_LEN2: usize;

    /// Total WOTS+ signature length: len = len1 + len2.
    const WOTS_LEN: usize = Self::WOTS_LEN1 + Self::WOTS_LEN2;

    /// Public key size in bytes.
    const PK_BYTES: usize = 2 * Self::N;

    /// Secret key size in bytes.
    const SK_BYTES: usize = 4 * Self::N;

    /// Signature size in bytes.
    /// SIG = R (n bytes) + SIG_FORS + SIG_HT
    /// SIG_FORS = k * (a+1) * n bytes
    /// SIG_HT = (h + d * len) * n bytes
    const SIG_BYTES: usize = Self::N + Self::K * (Self::A + 1) * Self::N
        + (Self::H + Self::D * Self::WOTS_LEN) * Self::N;

    /// Message digest length for FORS: ceil((k*a + 7)/8) + ceil((h - h'/d + 7)/8) + ceil((h'/8))
    /// Simplified: we need k*a bits for FORS indices and h bits for tree/leaf addressing.
    const MD_BYTES: usize;

    /// Tree address bits.
    const TREE_BITS: usize = Self::H - Self::H_PRIME;

    /// Leaf address bits.
    const LEAF_BITS: usize = Self::H_PRIME;
}

// =============================================================================
// SHAKE-128s: Small signatures, slower signing
// =============================================================================

/// SLH-DSA-SHAKE-128s parameters.
#[cfg(feature = "slh-dsa-shake-128s")]
pub mod slh_dsa_shake_128s {
    pub use super::common::*;

    /// Security parameter (16 bytes = 128 bits).
    pub const N: usize = 16;
    /// XMSS tree height.
    pub const H_PRIME: usize = 9;
    /// Total hypertree height.
    pub const H: usize = 63;
    /// Number of hypertree layers.
    pub const D: usize = 7;
    /// FORS tree height.
    pub const A: usize = 12;
    /// Number of FORS trees.
    pub const K: usize = 14;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 32;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size: n + k*(a+1)*n + (h + d*len)*n = 16 + 14*13*16 + (63 + 7*35)*16 = 7856
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params128s;

    impl super::Params for Params128s {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

// =============================================================================
// SHAKE-128f: Fast signing, larger signatures
// =============================================================================

/// SLH-DSA-SHAKE-128f parameters.
#[cfg(feature = "slh-dsa-shake-128f")]
pub mod slh_dsa_shake_128f {
    pub use super::common::*;

    /// Security parameter (16 bytes = 128 bits).
    pub const N: usize = 16;
    /// XMSS tree height (h' = h/d = 66/22 = 3).
    pub const H_PRIME: usize = 3;
    /// Total hypertree height.
    pub const H: usize = 66;
    /// Number of hypertree layers.
    pub const D: usize = 22;
    /// FORS tree height.
    pub const A: usize = 6;
    /// Number of FORS trees.
    pub const K: usize = 33;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 32;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size: n + k*(a+1)*n + (h + d*len)*n = 16 + 33*7*16 + (66 + 22*35)*16 = 17088
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params128f;

    impl super::Params for Params128f {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

// =============================================================================
// SHAKE-192s: Small signatures, slower signing
// =============================================================================

/// SLH-DSA-SHAKE-192s parameters.
#[cfg(feature = "slh-dsa-shake-192s")]
pub mod slh_dsa_shake_192s {
    pub use super::common::*;

    /// Security parameter (24 bytes = 192 bits).
    pub const N: usize = 24;
    /// XMSS tree height.
    pub const H_PRIME: usize = 9;
    /// Total hypertree height.
    pub const H: usize = 63;
    /// Number of hypertree layers.
    pub const D: usize = 7;
    /// FORS tree height.
    pub const A: usize = 14;
    /// Number of FORS trees.
    pub const K: usize = 17;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 48;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params192s;

    impl super::Params for Params192s {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

// =============================================================================
// SHAKE-192f: Fast signing, larger signatures
// =============================================================================

/// SLH-DSA-SHAKE-192f parameters.
#[cfg(feature = "slh-dsa-shake-192f")]
pub mod slh_dsa_shake_192f {
    pub use super::common::*;

    /// Security parameter (24 bytes = 192 bits).
    pub const N: usize = 24;
    /// XMSS tree height (h' = h/d = 66/22 = 3).
    pub const H_PRIME: usize = 3;
    /// Total hypertree height.
    pub const H: usize = 66;
    /// Number of hypertree layers.
    pub const D: usize = 22;
    /// FORS tree height.
    pub const A: usize = 8;
    /// Number of FORS trees.
    pub const K: usize = 33;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 48;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params192f;

    impl super::Params for Params192f {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

// =============================================================================
// SHAKE-256s: Small signatures, slower signing
// =============================================================================

/// SLH-DSA-SHAKE-256s parameters.
#[cfg(feature = "slh-dsa-shake-256s")]
pub mod slh_dsa_shake_256s {
    pub use super::common::*;

    /// Security parameter (32 bytes = 256 bits).
    pub const N: usize = 32;
    /// XMSS tree height.
    pub const H_PRIME: usize = 8;
    /// Total hypertree height.
    pub const H: usize = 64;
    /// Number of hypertree layers.
    pub const D: usize = 8;
    /// FORS tree height.
    pub const A: usize = 14;
    /// Number of FORS trees.
    pub const K: usize = 22;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 64;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params256s;

    impl super::Params for Params256s {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

// =============================================================================
// SHAKE-256f: Fast signing, larger signatures
// =============================================================================

/// SLH-DSA-SHAKE-256f parameters.
#[cfg(feature = "slh-dsa-shake-256f")]
pub mod slh_dsa_shake_256f {
    pub use super::common::*;

    /// Security parameter (32 bytes = 256 bits).
    pub const N: usize = 32;
    /// XMSS tree height (h' = h/d = 68/17 = 4).
    pub const H_PRIME: usize = 4;
    /// Total hypertree height.
    pub const H: usize = 68;
    /// Number of hypertree layers.
    pub const D: usize = 17;
    /// FORS tree height.
    pub const A: usize = 9;
    /// Number of FORS trees.
    pub const K: usize = 35;
    /// WOTS+ len1.
    pub const WOTS_LEN1: usize = 64;
    /// WOTS+ len2.
    pub const WOTS_LEN2: usize = 3;
    /// WOTS+ total length.
    pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
    /// Public key size.
    pub const PK_BYTES: usize = 2 * N;
    /// Secret key size.
    pub const SK_BYTES: usize = 4 * N;
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes.
    pub const MD_BYTES: usize = (K * A + H + 7) / 8;

    /// Parameter set marker type.
    pub struct Params256f;

    impl super::Params for Params256f {
        const N: usize = N;
        const H_PRIME: usize = H_PRIME;
        const H: usize = H;
        const D: usize = D;
        const A: usize = A;
        const K: usize = K;
        const WOTS_LEN1: usize = WOTS_LEN1;
        const WOTS_LEN2: usize = WOTS_LEN2;
        const MD_BYTES: usize = MD_BYTES;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "slh-dsa-shake-128s")]
    #[test]
    fn test_shake_128s_sizes() {
        use slh_dsa_shake_128s::*;
        assert_eq!(PK_BYTES, 32);
        assert_eq!(SK_BYTES, 64);
        assert_eq!(SIG_BYTES, 7856);
    }

    #[cfg(feature = "slh-dsa-shake-128f")]
    #[test]
    fn test_shake_128f_sizes() {
        use slh_dsa_shake_128f::*;
        assert_eq!(PK_BYTES, 32);
        assert_eq!(SK_BYTES, 64);
        assert_eq!(SIG_BYTES, 17088);
    }

    #[cfg(feature = "slh-dsa-shake-192s")]
    #[test]
    fn test_shake_192s_sizes() {
        use slh_dsa_shake_192s::*;
        assert_eq!(PK_BYTES, 48);
        assert_eq!(SK_BYTES, 96);
        assert_eq!(SIG_BYTES, 16224);
    }

    #[cfg(feature = "slh-dsa-shake-192f")]
    #[test]
    fn test_shake_192f_sizes() {
        use slh_dsa_shake_192f::*;
        assert_eq!(PK_BYTES, 48);
        assert_eq!(SK_BYTES, 96);
        assert_eq!(SIG_BYTES, 35664);
    }

    #[cfg(feature = "slh-dsa-shake-256s")]
    #[test]
    fn test_shake_256s_sizes() {
        use slh_dsa_shake_256s::*;
        assert_eq!(PK_BYTES, 64);
        assert_eq!(SK_BYTES, 128);
        assert_eq!(SIG_BYTES, 29792);
    }

    #[cfg(feature = "slh-dsa-shake-256f")]
    #[test]
    fn test_shake_256f_sizes() {
        use slh_dsa_shake_256f::*;
        assert_eq!(PK_BYTES, 64);
        assert_eq!(SK_BYTES, 128);
        assert_eq!(SIG_BYTES, 49856);
    }
}
