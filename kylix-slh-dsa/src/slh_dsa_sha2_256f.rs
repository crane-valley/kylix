//! SLH-DSA-SHA2-256f implementation.
//!
//! Fast variant with 256-bit security using SHA2-256.
//! Signature size: 49,856 bytes

use crate::hash_sha2::Sha2_256Hash;
use crate::params::slh_dsa_sha2_256f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaSha2_256f,
    hash_type: Sha2_256Hash,
    sk_size: 128,
    pk_size: 64,
    sig_size: 49856
);
