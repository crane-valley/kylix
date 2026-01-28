//! SLH-DSA-SHAKE-128f implementation.
//!
//! Fast variant with 128-bit security using SHAKE256.
//! Signature size: 17,088 bytes

use crate::hash_shake::Shake128Hash;
use crate::params::slh_dsa_shake_128f::*;

crate::types::define_slh_dsa_variant!(
    variant_name: SlhDsaShake128f,
    hash_type: Shake128Hash,
    sk_size: 64,
    pk_size: 32,
    sig_size: 17088
);
