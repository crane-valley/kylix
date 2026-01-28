//! SLH-DSA-SHAKE-192s implementation.
//!
//! Small variant with 192-bit security using SHAKE256.
//! Signature size: 16,224 bytes

use crate::hash_shake::Shake192Hash;
use crate::params::slh_dsa_shake_192s::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaShake192s,
    hash_type: Shake192Hash,
    sk_size: 96,
    pk_size: 48,
    sig_size: 16224
);
