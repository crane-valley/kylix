//! SLH-DSA-SHA2-256s implementation.
//!
//! Small signature variant with 256-bit security using SHA2-256.
//! Signature size: 29,792 bytes

use crate::hash_sha2::Sha2_256Hash;
use crate::params::slh_dsa_sha2_256s::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaSha2_256s,
    hash_type: Sha2_256Hash,
    sk_size: 128,
    pk_size: 64,
    sig_size: 29792
);
