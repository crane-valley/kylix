//! SLH-DSA-SHAKE-256f implementation.
//!
//! Fast variant with 256-bit security using SHAKE256.
//! Signature size: 49,856 bytes

use crate::hash_shake::Shake256Hash;
use crate::params::slh_dsa_shake_256f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaShake256f,
    hash_type: Shake256Hash,
    sk_size: 128,
    pk_size: 64,
    sig_size: 49856
);
