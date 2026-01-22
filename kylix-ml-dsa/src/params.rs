//! ML-DSA parameter sets
//!
//! Defines constants for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

use crate::reduce::Q;

/// Common parameters shared across all ML-DSA variants.
pub mod common {
    use super::*;

    /// Ring dimension
    pub const N: usize = 256;

    /// Modulus q = 8380417
    pub const Q_VAL: i32 = Q;

    /// Number of bits in q (23)
    pub const Q_BITS: usize = 23;

    /// d parameter for Power2Round (13)
    pub const D: usize = 13;

    /// Seed size in bytes
    pub const SEED_BYTES: usize = 32;

    /// CRH output size in bytes (64)
    pub const CRH_BYTES: usize = 64;
}

/// ML-DSA-44 parameters (NIST Level 2)
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    pub use super::common::*;

    /// Number of rows in matrix A
    pub const K: usize = 4;
    /// Number of columns in matrix A
    pub const L: usize = 4;
    /// Noise parameter for secret
    pub const ETA: usize = 2;
    /// Number of +/-1 coefficients in challenge
    pub const TAU: usize = 39;
    /// Bound on z coefficients (TAU * ETA)
    pub const BETA: i32 = 78;
    /// Masking range for y
    pub const GAMMA1: i32 = 1 << 17; // 2^17
    /// Low-order rounding range
    pub const GAMMA2: i32 = (Q_VAL - 1) / 88; // 95232
    /// Maximum number of hint ones
    pub const OMEGA: usize = 80;

    /// Challenge seed size (2λ/8 where λ=128)
    pub const C_TILDE_BYTES: usize = 32;

    /// Public key size in bytes
    pub const PK_BYTES: usize = 1312;
    /// Secret key size in bytes
    pub const SK_BYTES: usize = 2560;
    /// Signature size in bytes
    pub const SIG_BYTES: usize = 2420;

    /// Encoded polynomial size (t1)
    pub const POLY_T1_PACKED_BYTES: usize = 320;
    /// Encoded polynomial size (t0)
    pub const POLY_T0_PACKED_BYTES: usize = 416;
    /// Encoded polynomial size (eta=2)
    pub const POLY_ETA_PACKED_BYTES: usize = 96;
    /// Encoded polynomial size (z, gamma1=2^17)
    pub const POLY_Z_PACKED_BYTES: usize = 576;
}

/// ML-DSA-65 parameters (NIST Level 3)
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    pub use super::common::*;

    /// Number of rows in matrix A
    pub const K: usize = 6;
    /// Number of columns in matrix A
    pub const L: usize = 5;
    /// Noise parameter for secret
    pub const ETA: usize = 4;
    /// Number of +/-1 coefficients in challenge
    pub const TAU: usize = 49;
    /// Bound on z coefficients
    pub const BETA: i32 = 196;
    /// Masking range for y
    pub const GAMMA1: i32 = 1 << 19; // 2^19
    /// Low-order rounding range
    pub const GAMMA2: i32 = (Q_VAL - 1) / 32; // 261888
    /// Maximum number of hint ones
    pub const OMEGA: usize = 55;

    /// Challenge seed size (2λ/8 where λ=192)
    pub const C_TILDE_BYTES: usize = 48;

    /// Public key size in bytes
    pub const PK_BYTES: usize = 1952;
    /// Secret key size in bytes
    pub const SK_BYTES: usize = 4032;
    /// Signature size in bytes
    pub const SIG_BYTES: usize = 3309;

    /// Encoded polynomial size (t1)
    pub const POLY_T1_PACKED_BYTES: usize = 320;
    /// Encoded polynomial size (t0)
    pub const POLY_T0_PACKED_BYTES: usize = 416;
    /// Encoded polynomial size (eta=4)
    pub const POLY_ETA_PACKED_BYTES: usize = 128;
    /// Encoded polynomial size (z, gamma1=2^19)
    pub const POLY_Z_PACKED_BYTES: usize = 640;
}

/// ML-DSA-87 parameters (NIST Level 5)
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    pub use super::common::*;

    /// Number of rows in matrix A
    pub const K: usize = 8;
    /// Number of columns in matrix A
    pub const L: usize = 7;
    /// Noise parameter for secret
    pub const ETA: usize = 2;
    /// Number of +/-1 coefficients in challenge
    pub const TAU: usize = 60;
    /// Bound on z coefficients
    pub const BETA: i32 = 120;
    /// Masking range for y
    pub const GAMMA1: i32 = 1 << 19; // 2^19
    /// Low-order rounding range
    pub const GAMMA2: i32 = (Q_VAL - 1) / 32; // 261888
    /// Maximum number of hint ones
    pub const OMEGA: usize = 75;

    /// Challenge seed size (2λ/8 where λ=256)
    pub const C_TILDE_BYTES: usize = 64;

    /// Public key size in bytes
    pub const PK_BYTES: usize = 2592;
    /// Secret key size in bytes
    pub const SK_BYTES: usize = 4896;
    /// Signature size in bytes
    pub const SIG_BYTES: usize = 4627;

    /// Encoded polynomial size (t1)
    pub const POLY_T1_PACKED_BYTES: usize = 320;
    /// Encoded polynomial size (t0)
    pub const POLY_T0_PACKED_BYTES: usize = 416;
    /// Encoded polynomial size (eta=2)
    pub const POLY_ETA_PACKED_BYTES: usize = 96;
    /// Encoded polynomial size (z, gamma1=2^19)
    pub const POLY_Z_PACKED_BYTES: usize = 640;
}
