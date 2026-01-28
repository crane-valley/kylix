//! SLH-DSA-SHAKE-192f implementation.
//!
//! Fast variant with 192-bit security using SHAKE256.
//! Signature size: 35,664 bytes

use crate::hash_shake::Shake192Hash;
use crate::params::slh_dsa_shake_192f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaShake192f,
    hash_type: Shake192Hash,
    sk_size: 96,
    pk_size: 48,
    sig_size: 35664
);
