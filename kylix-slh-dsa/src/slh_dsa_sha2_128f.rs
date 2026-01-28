//! SLH-DSA-SHA2-128f implementation.
//!
//! Fast variant with 128-bit security using SHA2-256.
//! Signature size: 17,088 bytes

use crate::hash_sha2::Sha2_128Hash;
use crate::params::slh_dsa_sha2_128f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaSha2_128f,
    hash_type: Sha2_128Hash,
    sk_size: 64,
    pk_size: 32,
    sig_size: 17088
);
