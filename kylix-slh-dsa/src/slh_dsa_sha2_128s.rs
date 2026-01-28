//! SLH-DSA-SHA2-128s implementation.
//!
//! Small signature variant with 128-bit security using SHA2-256.
//! Signature size: 7,856 bytes

use crate::hash_sha2::Sha2_128Hash;
use crate::params::slh_dsa_sha2_128s::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaSha2_128s,
    hash_type: Sha2_128Hash,
    sk_size: 64,
    pk_size: 32,
    sig_size: 7856
);
