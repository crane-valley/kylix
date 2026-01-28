//! SLH-DSA-SHAKE-256s implementation.
//!
//! Small variant with 256-bit security using SHAKE256.
//! Signature size: 29,792 bytes

use crate::hash_shake::Shake256Hash;
use crate::params::slh_dsa_shake_256s::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaShake256s,
    hash_type: Shake256Hash,
    sk_size: 128,
    pk_size: 64,
    sig_size: 29792
);
