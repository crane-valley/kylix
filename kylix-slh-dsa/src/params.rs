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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
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
    pub const MD_BYTES: usize = (K * A + H).div_ceil(8);
}

// =============================================================================
// SHA2-128s: Small signatures, slower signing (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-128s parameters.
#[cfg(feature = "slh-dsa-sha2-128s")]
pub mod slh_dsa_sha2_128s {
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
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    /// FIPS 205 Section 11.1: m = ceil(k*a/8) + ceil(tree_bits/8) + ceil(leaf_bits/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

// =============================================================================
// SHA2-128f: Fast signing, larger signatures (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-128f parameters.
#[cfg(feature = "slh-dsa-sha2-128f")]
pub mod slh_dsa_sha2_128f {
    pub use super::common::*;

    /// Security parameter (16 bytes = 128 bits).
    pub const N: usize = 16;
    /// XMSS tree height.
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
    /// Signature size.
    pub const SIG_BYTES: usize = N + K * (A + 1) * N + (H + D * WOTS_LEN) * N;
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

// =============================================================================
// SHA2-192s: Small signatures, slower signing (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-192s parameters.
#[cfg(feature = "slh-dsa-sha2-192s")]
pub mod slh_dsa_sha2_192s {
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
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

// =============================================================================
// SHA2-192f: Fast signing, larger signatures (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-192f parameters.
#[cfg(feature = "slh-dsa-sha2-192f")]
pub mod slh_dsa_sha2_192f {
    pub use super::common::*;

    /// Security parameter (24 bytes = 192 bits).
    pub const N: usize = 24;
    /// XMSS tree height.
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
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

// =============================================================================
// SHA2-256s: Small signatures, slower signing (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-256s parameters.
#[cfg(feature = "slh-dsa-sha2-256s")]
pub mod slh_dsa_sha2_256s {
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
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

// =============================================================================
// SHA2-256f: Fast signing, larger signatures (SHA2-based)
// =============================================================================

/// SLH-DSA-SHA2-256f parameters.
#[cfg(feature = "slh-dsa-sha2-256f")]
pub mod slh_dsa_sha2_256f {
    pub use super::common::*;

    /// Security parameter (32 bytes = 256 bits).
    pub const N: usize = 32;
    /// XMSS tree height.
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
    /// Message digest bytes: ceil(k*a/8) + ceil((h-h')/8) + ceil(h'/8)
    pub const MD_BYTES: usize =
        (K * A).div_ceil(8) + (H - H_PRIME).div_ceil(8) + H_PRIME.div_ceil(8);
}

#[cfg(all(test, feature = "any-variant"))]
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

    // SHA2 variant tests (same sizes as SHAKE variants)

    #[cfg(feature = "slh-dsa-sha2-128s")]
    #[test]
    fn test_sha2_128s_sizes() {
        use slh_dsa_sha2_128s::*;
        assert_eq!(PK_BYTES, 32);
        assert_eq!(SK_BYTES, 64);
        assert_eq!(SIG_BYTES, 7856);
    }

    #[cfg(feature = "slh-dsa-sha2-128f")]
    #[test]
    fn test_sha2_128f_sizes() {
        use slh_dsa_sha2_128f::*;
        assert_eq!(PK_BYTES, 32);
        assert_eq!(SK_BYTES, 64);
        assert_eq!(SIG_BYTES, 17088);
    }

    #[cfg(feature = "slh-dsa-sha2-192s")]
    #[test]
    fn test_sha2_192s_sizes() {
        use slh_dsa_sha2_192s::*;
        assert_eq!(PK_BYTES, 48);
        assert_eq!(SK_BYTES, 96);
        assert_eq!(SIG_BYTES, 16224);
    }

    #[cfg(feature = "slh-dsa-sha2-192f")]
    #[test]
    fn test_sha2_192f_sizes() {
        use slh_dsa_sha2_192f::*;
        assert_eq!(PK_BYTES, 48);
        assert_eq!(SK_BYTES, 96);
        assert_eq!(SIG_BYTES, 35664);
    }

    #[cfg(feature = "slh-dsa-sha2-256s")]
    #[test]
    fn test_sha2_256s_sizes() {
        use slh_dsa_sha2_256s::*;
        assert_eq!(PK_BYTES, 64);
        assert_eq!(SK_BYTES, 128);
        assert_eq!(SIG_BYTES, 29792);
    }

    #[cfg(feature = "slh-dsa-sha2-256f")]
    #[test]
    fn test_sha2_256f_sizes() {
        use slh_dsa_sha2_256f::*;
        assert_eq!(PK_BYTES, 64);
        assert_eq!(SK_BYTES, 128);
        assert_eq!(SIG_BYTES, 49856);
    }
}
