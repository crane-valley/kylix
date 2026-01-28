//! SLH-DSA-SHA2-192f implementation.
//!
//! Fast variant with 192-bit security using SHA2-256.
//! Signature size: 35,664 bytes

use crate::hash_sha2::Sha2_192Hash;
use crate::params::slh_dsa_sha2_192f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaSha2_192f,
    hash_type: Sha2_192Hash,
    sk_size: 96,
    pk_size: 48,
    sig_size: 35664
);
